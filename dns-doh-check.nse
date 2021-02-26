local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local strbuf = require "strbuf"
local base64 = require "base64"

description = [[
Performs a checking of DoH service against the target host and port
]]

---
-- @usage
-- nmap --script=dns-doh-check -p443 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | dns-doh-check:
-- |   DoH-GET-PARAMS: false
-- |   DoH-BASE64-PARAM: true
-- |_  DoH-POST: false
--
---

author = {"Tomas Cejka","cejkat@cesnet.cz"}
license = "Creative Commons https://creativecommons.org/licenses/by-nc-sa/4.0/"
categories = { "discovery" }
portrule = shortport.http

action = function(host,port)

     local results = {}

     -- construct the query string, the path in the DOH HTTPS GET
     local basequery = "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
     -- define the header value (which defines the output type)
     local options = {header={}}
     options['redirect_ok'] = function(host, port)
         local c = 5
         return function(url)
            if ( c==0 ) then return false end
            c = c - 1
            return true
         end
     end

     local response = http.get(host.ip, port.number, '/dns-query?name=www.example.com&type=A', options)
     if response.status == 200 then
         results["DoH-GET-PARAMS"] = true
     else
         results["DoH-GET-PARAMS"] = false
     end

     response = http.get(host.ip, port.number, '/dns-query?dns='..basequery, options)
     if response.status == 200 then
         results["DoH-BASE64-PARAM"] = true
     else
         results["DoH-BASE64-PARAM"] = false
     end

     options['header']['Content-Type'] = 'application/dns-message'
     qstring = base64.dec(basequery)

     response = http.post(host.ip, port.number, "/dns-query", options, "", qstring)
     if response.status == 200 then
         results["DoH-POST"] = true
     else
         results["DoH-POST"] = false
     end

     return results
end

