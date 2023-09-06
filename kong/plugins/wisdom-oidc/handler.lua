local re_gmatch = ngx.re.gmatch
local resty = require "resty.http"
local cjson = reqire "cjson"

-- now define the plugin with the priority and version
local plugin = {
    PRIORITY = 1000,
    VERSION = "1.0.0"
}


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
            return kong.response.exit(500, [[
                {
                    "code": "gateway.SSL_HANDSHAKE_FAIL",
                    "title": "SSL Handshake Failed",
                    "description": "unable to look up 'userinfo' endpoint: ssl handshake failed",
                    "httpCode": 500,
                    "httpError": "Internal Server Error"
                }
                ]]
            )
        end
    end

    -- since now all preparations are done, query the discovery uri
    local response, err = http_client:request(request)

    -- now check if an error occurred
    if not response then
        kong.log.err(err)
        return kong.response.exit(500, [[
            {
                "code": "gateway.NO_DISCOVERY_RESPONSE",
                "title": "No response received",
                "description": "unable to look up 'userinfo' endpoint: no response received from idp",
                "httpCode": 500,
                "httpError": "Internal Server Error"
            }
            ]]
        )
    end

    -- now check the status code that has been sent back by the userinfo 
    -- endpoint
    if response.status != 200 then
        kong.log.err("discovery endpoint returned non-200 response")
        return kong.response.exit(500, [[
            {
                "code": "gateway.UNEXPECTED_HTTP_CODE",
                "title": "Unexpected Response HTTP Code in response",
                "description": "unable to look up 'userinfo' endpoint: response contained a non-200 response code",
                "httpCode": 500,
                "httpError": "Internal Server Error"
            }
            ]]
        )
    end

    -- now read the contents of the response and decode them
    local response_body = response:read_body()
    local decoding_successful, discovery_result = pcall(cjson.decode, response_body)

    -- now check if the decoding was successful
    if not decoding_successful then
        kong.log.err("json decoding of discovery response failed")
        return kong.response.exit(500, [[
            {
                "code": "gateway.DISCOVERY_JSON_INVALID",
                "title": "Discovery Response Invalid",
                "description": "unable to look up 'userinfo' endpoint: response is not decodable from json",
                "httpCode": 500,
                "httpError": "Internal Server Error"
            }
            ]]
        )
    end

    -- now check if the response contains the userinfo endpoint
    if not discovery_result['userinfo_endpoint'] then
        kong.log.err("discovery result lacks userinfo_endpoint")
        return kong.response.exit(500, [[
            {
                "code": "gateway.DISCOVERY_MISSING_USERINFO_ENDPOINT",
                "title": "Discovery lacks userinfo endpoint",
                "description": "unable to look up 'userinfo' endpoint: response does not contain the userinfo_discovery field",
                "httpCode": 500,
                "httpError": "Internal Server Error"
            }
            ]]
        )
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
        return kong.response.exit(401, [[
            {
                "code": "gateway.MISSING_AUTHORIZATION_HEADER",
                "title": "Request Missing Authorization Header",
                "description": "the request did not contain the 'Authorization' header. please check your request",
                "httpCode": 401,
                "httpError": "Unauthorized"
            }
            ]]
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

