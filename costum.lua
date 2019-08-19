-- Funktion die ueberschrieben wird zunaechst sichern
dovecot_orig_configure = require("dovecot").addMailbox

LC.dovecot = require("dovecot")

-- pattern for "userdb_sieve" setting in /etc/dovecot/passwd
if USERDB_SIEVE == nil then
  USERDB_SIEVE = "userdb_sieve=/var/mail/%C/%I/default.sieve"
end

-- pattern for "userdb_sieve_storage" setting in /etc/dovecot/passwd
if USERDB_SIEVE_STORAGE == nil then
  USERDB_SIEVE_STORAGE = "userdb_sieve_storage=/var/mail/%C/%I/sieve/"
end

-- pattern for "userdb_sieve_before" setting in /etc/dovecot/passwd
if USERDB_SIEVE_BEFORE == nil then
  USERDB_SIEVE_BEFORE = "userdb_sieve_before=/var/mail/%C/%I/dovecot.sieve"
end

function LC.dovecot.addMailbox(cfg, opts, data)
  -- Erst Konfiguration erzeugen lassen und danach anpassen
  res = dovecot_orig_configure(cfg,opts, data)

    local userfile  = cfg["userfile"]
    if opts and opts.prefix then
      -- use prefix (for testing etc.)
      userfile = opts.prefix .. userfile
    end

    LC.log.print(LC.log.INFO, "Adding/updating user account " .. data.name .. "@" .. data.domain .. " at dovecot config file: " .. userfile)

    -- get uid and gid for user "mail"
    local uid = LC.sys.user_exists("mail")
    if uid == false then
      return false, "System user 'mail' does not exist, please create user"
    end
    local gid = LC.sys.group_exists("mail")
    if gid == false then
      return false, "System group 'mail' does not exist, please create group"
    end

    -- check if subscription directory already exists, otherwise create it:
    if not LC.fs.is_dir('/var/mail/' .. data.contract) then
      if LC.fs.is_file('/var/mail/' .. data.contract) then
        os.remove('/var/mail/' .. data.contract)
      end
      LC.fs.mkdir_rec('/var/mail/' .. data.contract)
      LC.fs.setperm('/var/mail/' .. data.contract, "2700", "mail", "mail")
    end

    -- check if mailbox directory already exists, otherwise create it:
    if not LC.fs.is_dir('/var/mail/' .. data.contract .. '/' .. data.id) then
      LC.fs.mkdir_rec('/var/mail/' .. data.contract .. '/' .. data.id)
      LC.fs.setperm('/var/mail/' .. data.contract .. '/' .. data.id, "2700", "mail", "mail")
    end

    -- check if sieve directory already exists, otherwise create it:
    if not LC.fs.is_dir('/var/mail/' .. data.contract .. '/' .. data.id .. '/sieve') then
      LC.fs.mkdir_rec('/var/mail/' .. data.contract .. '/' .. data.id .. '/sieve')
      LC.fs.setperm('/var/mail/' .. data.contract .. '/' .. data.id .. '/sieve', "2700", "mail", "mail")
    end
    
    -- add entry to user file
     local fhr, fhw, msg
     if not LC.fs.is_file(userfile) then
       fhr, msg = io.open(userfile, "a")
       if fhr == nil then
         LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for appending: ", msg)
         return false, "Can't open '" .. userfile .. "' for appending: " .. msg
       end
       -- adjust owner & permissions - only Dovecot needs access to this file, so set mod 600 !!!
       LC.fs.setperm(userfile, "0600", "dovecot", "root")
       fhr:close()
     end

     fhr, msg = io.open(userfile, "r")
     if fhr == nil then
       LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for reading: ", msg)
       return false, "Can't open '" .. userfile .. "' for reading: " .. msg
     end

     fhw, msg = io.open(userfile .. ".tmp", "w")
     if fhw == nil then
       LC.log.print(LC.log.ERR, "Can't open '", userfile .. ".tmp", "' for writing: ", msg)
       fhr:close()
       return false, "Can't open '" .. userfile .. ".tmp" .. "' for writing: " .. msg
     end
     -- adjust owner & permissions - only Dovecot needs to read this file:
     LC.fs.setperm(userfile .. ".tmp", "0600", "dovecot", "root")

     -- build new/updated entry:
     local new_line = nil
     if data.mailbox == true or data.autoresponder == true then
       local pwd, algo
       if data.mailbox == false or data.password == nil then
         pwd = "!"
         algo = ""
       elseif string.len(data.password) == 74 and string.match(data.password, "^{CRAM%-MD5}") then
         -- pre-hashed password - use without modification
         pwd = data.password
         algo = ""
       elseif string.len(data.password) == 34 and string.match(data.password, "^$1$[%w./][%w./][%w./][%w./][%w./][%w./][%w./][%w./]$[%w./]+$") then
         -- MD5-CRYPT password (propably imported via SOAP interface)
         pwd = data.password
         algo = "{MD5-CRYPT}"
       else
         -- create CRAM-MD5 hash
         pwd = LC.crypt.cram_md5(data.password)
         algo = "{CRAM-MD5}"
       end
       local p_home = replace_pattern(HOME, data)
       local p_mail = replace_pattern(USERDB_MAIL, data)
       local p_sieve = replace_pattern(USERDB_SIEVE, data)
       local p_sieve_storage = replace_pattern(USERDB_SIEVE_STORAGE, data)
       local p_sieve_before = replace_pattern(USERDB_SIEVE_BEFORE, data)

       new_line = data.name .. "@" .. data.domain .. ":" .. algo .. pwd .. ":" .. uid .. ":" .. gid .. "::" .. p_home .. "::"
       if p_mail ~= "" then
         -- userdb_mail:
         new_line = new_line .. p_mail
       end
       if data.quota ~= nil and data.quota > 0 then
         -- userdb_quota_rule:
         new_line = new_line .. " userdb_quota_rule=*:storage=" .. data.quota .. "MB"
       end
       if p_sieve ~= "" then
         -- userdb_sieve:
         new_line = new_line .. " " .. p_sieve
       end
       if p_sieve_storage ~= "" then
         -- userdb_sieve_storage:
         new_line = new_line .. " " .. p_sieve_storage
       end
       if p_sieve_before ~= "" then
         -- userdb_sieve_before:
         new_line = new_line .. " " .. p_sieve_before
       end
     end

     -- search/replace existing entry
     local search
     if data.old_addr == nil then
       search = "^" .. data.name .. "@" .. data.domain .. ":"
     else
       -- rename existing mailbox
       search = "^" .. data.old_addr .. ":"
     end
     search = string.gsub(search, "%%", "%%%%")
     search = string.gsub(search, "%.", "%%.")
     search = string.gsub(search, "%+", "%%+")
     search = string.gsub(search, "%-", "%%-")
     search = string.gsub(search, "%*", "%%*")
     local line
     local found = false
     while true do
       line = fhr:read()
       if line == nil then break end
       if string.find(line, search) ~= nil then
         found = true
         if new_line ~= nil then
           fhw:write(new_line, "\n")
         end
       elseif line ~= "" then
         fhw:write(line, "\n")
       end
     end

     fhr:close()

     if found == false and new_line ~= nil then
       -- append new entry
       fhw:write(new_line, "\n")
     end

     fhw:close()

     -- move temporary file to new password file
  LC.fs.rename(userfile .. ".tmp", userfile)

  -- check for autoresponder
  local sievepath = "/var/mail/" .. data.contract .. "/" .. data.id
  if data.autoresponder == true then
    -- create autoresponder
    fhw, msg = io.open(sievepath .. "/dovecot.sieve.tmp", "w")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", sievepath .. "/dovecot.sieve.tmp", "' for writing: ", msg)
      return false, "Can't open '" .. sievepath .. "/dovecot.sieve.tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Dovecot (mail) needs to read this file:
    LC.fs.setperm(sievepath .. "/dovecot.sieve.tmp", "0640", "mail", "mail")
    -- escape quotes
    local as = string.gsub(data.autosubject, "\\", "\\\\")
    as = string.gsub(as, "\"", "\\\"")
    local am = string.gsub(data.automessage, "\\", "\\\\")
    am = string.gsub(am, "\"", "\\\"")
    local useVars = string.match(as, "${subject}") or string.match(am, "${subject}")
    fhw:write("# Created by LiveConfig\n")
    if useVars then
      fhw:write("require [\"date\", \"relational\", \"vacation\", \"variables\"];\n")
      fhw:write("if header :matches \"subject\" \"*\" {\n")
      fhw:write("  set \"subject\" \"${1}\";\n")
      fhw:write("}\n")
    else
      fhw:write("require [\"date\", \"relational\", \"vacation\"];\n")
    end
    -- only send auto-reply if message is NOT tagges as spam:
    if data.autoreplyend ~= nil then
      fhw:write("if allof(not header :contains \"X-Spam-Flag\" \"YES\",\n")
      fhw:write("         currentdate :value \"lt\" \"date\" \"", data.autoreplyend, "\") {\n")
    else
      fhw:write("if not header :contains \"X-Spam-Flag\" \"YES\" {\n")
    end
    fhw:write("  vacation\n")
    fhw:write("    :days 1\n")
    fhw:write("    :subject \"", as, "\"\n")
    fhw:write("    :addresses [\"", data.name, "@", data.domain, "\"")
    if type(data.aliases) == "table" then
      local i,s
      for i, s in ipairs(data.aliases) do
        fhw:write(", \"", s, "@", data.domain, "\"")
      end
    end
    fhw:write("]\n")
    fhw:write("    \"", am, "\";\n")
    fhw:write("}\n")
    if not data.mailbox then
      -- no real mailbox (forward-only), so discard message:
      fhw:write("discard;\n")
    end
    fhw:close()
    LC.fs.rename(sievepath .. "/dovecot.sieve.tmp", sievepath .. "/dovecot.sieve")
  else
    -- delete autoresponder if still existing...
    if LC.fs.is_file(sievepath .. "/dovecot.sieve") and not LC.fs.is_symlink(sievepath .. "/dovecot.sieve") then
      os.remove(sievepath .. "/dovecot.sieve")
      os.remove(sievepath .. "/dovecot.svbin")
    end
  end

  return true

  end
