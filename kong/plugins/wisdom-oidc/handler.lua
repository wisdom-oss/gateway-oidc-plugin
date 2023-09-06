local re_gmatch = ngx.re.gmatch
local resty = require "resty.http"
local cjson = require "cjson"

-- now define the plugin with the priority and version
local plugin = {
    PRIORITY = 1000,
    VERSION = "1.0.0"
}

function plugin:generate_error(code, title, description, httpCode, httpCodeString)
    return {
        code = code,
        title = title,
        description = description,
        httpCode = httpCode,
        httpStatus = httpCodeString
    }
end

function plugin:generate_internal_error(code, title, description, error)
    -- return an object
    return plugin:generate_error(code, title, description .. ": " .. error, 500, "Internal Server Error")
end


-- this function is used to check which endpoint the user info request needs
-- to be directed to.
function plugin:resolve_userinfo_endpoint(discovery_uri)
    -- parse the uri and resolve the scheme, host, port and path for the
    -- discovery request
    local scheme, host, port, path = unpack(resty:parse_uri(discovery_uri))

    -- now build a new request to the endpoint
    local request = {
        method = "GET",
        path = path
    }

    -- now create a new http client
    local http_client = resty.new()
    -- now set the timeout to 10 seconds
    http_client:set_timeout(10000)
    -- now connect the the idp host
    http_client:connect(host, port)
    -- now check the scheme used to access the idp
    if scheme == "https" then
        -- since https is being used, try to make the ssl handshake
        local handshake_ok, err = http_client:ssl_handshake()
        if not handshake_ok then
            -- since the handshake failed return an error
            kong.log.err(err)
            local response = plugin:generate_internal_error(
                "SSL_HANDSHAKE_FAILED",
                "SSL Handshake Failed",
                "unable to look up userinfo endpoint",
                err
            )
            return kong.response.exit(500, cjson.encode(response))
        end
    end

    -- since now all preparations are done, query the discovery uri
    local response, err = http_client:request(request)

    if err then
        kong.log.err(err)
        local response = plugin:generate_internal_error(
            "DISCOVERY_REQUEST_FAILED",
            "OpenID Connect Discovery Failed",
            "an unknown error occurred during the lookup",
            err
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now check if an error occurred
    if not response then
        local response = plugin:generate_internal_error(
            "NO_DISCOVERY_RESPONSE",
            "No discovery response",
            "unable to look up userinfo endpoint",
            "empty response"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now check the status code that has been sent back by the userinfo 
    -- endpoint
    if not response.status == 200 then
        kong.log.err("discovery endpoint returned non-200 response")
        local response = plugin:generate_internal_error(
            "DISCOVERY_RESULT_NON_200",
            "Discovery Call failed",
            "unable to get information from discovery endpoint",
            "response was not 200"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now read the contents of the response and decode them
    local response_body = response:read_body()
    local decoding_successful, discovery_result = pcall(cjson.decode, response_body)

    -- now check if the decoding was successful
    if not decoding_successful then
        kong.log.err("json decoding of discovery response failed")
        local response = plugin:generate_internal_error(
            "JSON_DECODING_FAILED",
            "Invalid JSON in Discovery",
            "unable to decode response from discovery endpoint",
            "json not recognized"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now check if the response contains the userinfo endpoint
    if not discovery_result['userinfo_endpoint'] then
        kong.log.err("discovery result lacks userinfo_endpoint")
        local response = plugin:generate_internal_error(
            "DISCOVERY_MISSING_USERINFO_ENDPOINT",
            "Userinfo endpoint not in discovery response",
            "unable to look up 'userinfo' endpoint",
            "response does not contain the 'userinfo_endpoint' field"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- since the userinfo endpoint is available, return it
    return discovery_result['userinfo_endpoint']
end

-- this function can be used to extract the value of the bearer token from the
-- authorizaton header
function plugin:extract_bearer_token()
    -- get the value of the authorization header
    local header_value = kong.request.get_header("authorization")
    if not authorization_header then
        return kong.response.exit(400, cjson.encode(plugin:generate_error(
                    "MISSING_AUTHORIZATION_HEADER",
                    "Missing Authorization Header",
                    "the authorization header is either not set or empty",
                    400,
                    "Bad Request"
                )
            )
        )
    end
    -- since the authorization header has a value, try to match the beader token
    local results, err = re_gmatch(header_value, "\\s*[Bb]earer\\s+(.+)")
    if not results then
       return nil, err
    end

    -- since a value has been matched get the results
    local matches, err = results()
    if err then
        return nil, err
    end

    if matches and #matches > 0 then
        return matches[1], nil
    end
end

-- this function actually implements the plugins logic
function plugin:access(config)
    -- check for the bearer token in the request
    local bearer_token, err = plugin:extract_bearer_token()
    if err then
        local response = plugin:generate_internal_error(
            "BEARER_TOKEN_EXTRATION_FAILED",
            "Bearer Token Extraction Failed",
            "The bearer token extraction failed",
            err
        )
        return kong.response.exit(500, cjson.encode(response))
    end
    if not bearer_token then
        local response = plugin:generate_error(
            "MISSING_BEARER_TOKEN",
            "No bearer token",
            "The bearer token in your request is empty or not recognized",
            401,
            "Unauthorized"
        )
        return kong.response.exit(401, cjson.encode(response))
    end

    -- since noe the bearer token has been extracted try to find the userinfo
    -- endpoint of the configured idp
    local userinfo_endpoint = plugin:resolve_userinfo_endpoint(config.oidc_discovery_url)
    if not userinfo_endpoint then
        local response = plugin:generate_error(
            "USERINFO_ENDPOINT_NOT_FOUND",
            "Userinfo endpoint not found",
            "the userinfo endpoint could not be identified",
            500,
            "Internal Server Error"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- since the userinfo endpoint and the bearer token are now known
    -- reuqest the userrinfo endpoint

    -- parse the uri
    local scheme, host, port, path = unpack(resty:parse_uri(userinfo_endpoint))

    -- build the request
    local userinfo_request = {
        method = "GET",
        path = path,
        headers = {
            ["Authorization"] = "Bearer " .. bearer_token
        }
    }

    -- now create a new http client
    local http_client = resty.new()
    http_client:set_timeout(10000)
    -- now connect to the host
    http_client:connect(host, port)
    -- now check the scheme of the userinfo endpoint
    if scheme == "https" then
        local handshake_ok, err = http_client:ssl_handshake()
        if not handshake_ok then
            kong.log.err(err)
            local response = plugin:generate_internal_error(
                "SSL_HANDSHAKE_FAIL",
                "SSL Handshake Failed",
                "unable to secure the connection to the idp",
                err
            )
            return kong.response.exit(500, cjson.encode(response))
        end
    end

    -- now execute the query
    local userinfo_response, err = http_client:request(userinfo_request)
    if err then
        kong.log.err(err)
        local response = plugin:generate_internal_error(
            "USERINFO_REQUEST_FAILED",
            "Userinfo Request Failed",
            "the request for the user info failed",
            err
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now get the response body
    local userinfo_response_body = userinfo_response:read_body()
    local userinfo_parsed, userinfo = pcall(cjson.decode, userinfo_response_body)
    if not userinfo_parsed then
        local response = plugin:generate_internal_error(
            "JSON_DECODING_FAILED",
            "Invalid JSON in userinfo response",
            "unable to decode response from userinfo endpoint",
            "json not recognized"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now check if the userinfo contains the username
    if not userinfo['preferred_username'] then
        local response = plugin:generate_internal_error(
            "INVALID_USERINFO_RESPONSE",
            "Invalid Userinfo",
            "the userinfo is missing a field",
            "'preferred_username' not found"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- now check if the user info contains the groups
    if not userinfo['groups'] then
        local response = plugin:generate_internal_error(
            "INVALID_USERINFO_RESPONSE",
            "Invalid Userinfo",
            "the userinfo is missing a field",
            "'groups' not found"
        )
        return kong.response.exit(500, cjson.encode(response))
    end

    -- since all required checks are done, get the username and groups into the
    -- reuest headers
    kong.service.request.set_header("X-WISdoM-User", userinfo['preferred_username'])
    kong.service.request.set_header("X-WISdoM-Groups", userinfo['groups'])

    -- now check if the isAdmin field is set
    if userinfo['isAdmin'] then
        kong.service.request.set_header("X-WISdoM-Admin", userinfo['isAdmin'])
    end
end

return plugin
