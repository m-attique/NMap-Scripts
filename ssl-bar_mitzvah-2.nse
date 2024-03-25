local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local nmap = require "nmap"

description = [[
Detects servers that support RC4 ciphers, indicating potential vulnerability to
the Bar Mitzvah attack (CVE-2015-2808). The Bar Mitzvah attack exploits
weaknesses in the RC4 encryption algorithm, particularly in SSL/TLS protocols.
]]

---
-- @usage
-- nmap --script ssl-bar_mitzvah -p 443 <host>
-- 
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | ssl-bar_mitzvah:
-- |   VULNERABLE:
-- |_    Server supports RC4 ciphers, vulnerable to Bar Mitzvah (CVE-2015-2808)

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "vuln"}

portrule = shortport.ssl

action = function(host, port)
    local condvar = nmap.condvar(host)
    local status, result = tls.connect(host, port, { protocol = "any", verify = false, ciphers = "RC4" })

    if not status then
        return stdnse.format_output(false, "Failed to connect or server does not support RC4 ciphers.")
    end

    local rc4_supported = false
    for _, cipher in ipairs(result.ciphers) do
        if string.find(cipher.name, "RC4") then
            rc4_supported = true
            break
        end
    end

    if rc4_supported then
        return stdnse.format_output(true, "Server supports RC4 ciphers, vulnerable to Bar Mitzvah (CVE-2015-2808)")
    else
        return stdnse.format_output(false, "Server does not support RC4 ciphers, not vulnerable to Bar Mitzvah.")
    end
end
