local typedefs = require "kong.db.schema.typedefs"

return {
    name = "wisdom-oidc",
    fields = {
        {
            consumer = typedefs.no_consumer
        },
        {
            protocols = typedefs.protocols_http
        },
        {
            config = {
                type = "record",
                fields = {
                    {oidc_discovery_url = {
                        type = "string",
                        required = true
                    }}
                }
            }
        }
    }
}