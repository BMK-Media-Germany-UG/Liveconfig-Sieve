orig_addMailbox = dovecot.addMailbox

local string = string
-- pattern for "userdb_sieve_storage" setting in /etc/dovecot/passwd
if USERDB_SIEVE_STORAGE == nil then
  USERDB_SIEVE_STORAGE = "userdb_sieve_storage=/var/mail/%C/%I/sieve/"
end

-- pattern for "userdb_sieve_before" setting in /etc/dovecot/passwd
if USERDB_SIEVE_BEFORE == nil then
  USERDB_SIEVE_BEFORE = "userdb_sieve_before=/var/mail/%C/%I/dovecot.sieve"
end

local function replace_pattern(var, data)
  var = string.gsub(var, "%%C", data.contract)
  var = string.gsub(var, "%%I", data.id)
  return var
end

function dovecot.addMailbox(cfg, opts, data)
  
    local sievepath = "/var/mail/" .. data.contract .. "/" .. data.id
    if LC.fs.is_file(sievepath .. "/dovecot.sieve") and LC.fs.is_symlink(sievepath .. "/dovecot.sieve") then
      LC.fs.rename(sievepath .. "/dovecot.sieve", sievepath .. "/symlink.sieve")
    end
  
    orig_return = orig_addMailbox(cfg, opts, data)

    local userfile  = cfg["userfile"]
    if opts and opts.prefix then
      -- use prefix (for testing etc.)
      userfile = opts.prefix .. userfile
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

       local p_sieve_storage = replace_pattern(USERDB_SIEVE_STORAGE, data)
       local p_sieve_before = replace_pattern(USERDB_SIEVE_BEFORE, data)

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
         local new_line = line
         if p_sieve_storage ~= "" then
           -- userdb_sieve_storage:
           new_line = new_line .. " " .. p_sieve_storage
         end
         if p_sieve_before ~= "" then
           -- userdb_sieve_before:
           new_line = new_line .. " " .. p_sieve_before
         end
         fhw:write(new_line, "\n")
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

    local sievepath = "/var/mail/" .. data.contract .. "/" .. data.id

    if LC.fs.is_file(sievepath .. "/dovecot.sieve") and not LC.fs.is_symlink(sievepath .. "/dovecot.sieve") then
      LC.fs.rename(sievepath .. "/dovecot.sieve", sievepath .. "/default.sieve")
      LC.exec('sievec ' .. sievepath .. "/default.sieve")
    end

    if not data.autoresponder == true then
      if LC.fs.is_file(sievepath .. "/default.sieve") and not LC.fs.is_symlink(sievepath .. "/default.sieve") then
        os.remove(sievepath .. "/default.sieve")
        os.remove(sievepath .. "/default.svbin")
      end
    end

    if LC.fs.is_file(sievepath .. "/symlink.sieve") then
      LC.fs.rename(sievepath .. "/symlink.sieve", sievepath .. "/dovecot.sieve")
    end

    if not LC.fs.is_file(sievepath .. "/dovecot.sieve") then
      if not LC.fs.is_file(sievepath .. "/sieve/default.sieve") then
        fhw, msg = io.open(sievepath .. "/sieve/default.sieve.tmp", "w")
        if fhw == nil then
          LC.log.print(LC.log.ERR, "Can't open '", sievepath .. "/sieve/default.sieve.tmp", "' for writing: ", msg)
          return false, "Can't open '" .. sievepath .. "/sieve/default.sieve.tmp" .. "' for writing: " .. msg
        end
        -- adjust owner & permissions - only Dovecot (mail) needs to read this file:
        LC.fs.setperm(sievepath .. "/sieve/default.sieve.tmp", "0640", "mail", "mail")
        fhw:write("")
        fhw:close()
        LC.fs.rename(sievepath .. "/sieve/default.sieve.tmp", sievepath .. "/sieve/default.sieve")
      end
      LC.exec('ln -s ' .. "sieve/default.sieve " .. sievepath .. '/dovecot.sieve')
    end
  
    return orig_return

end
