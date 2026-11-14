-- CI-only atomic config generation prototype, not yet integrated into Control Center.
-- KEYS[1] must use ci: namespace; argv expected,new,sha,ttl_seconds
if not string.match(KEYS[1], '^ci:') then
    return redis.error_reply('BAD_KEY_NAMESPACE')
end
local current = redis.call('HGET', KEYS[1], 'revision') or '0'
if current ~= ARGV[1] then
    return redis.error_reply('STALE_REVISION')
end
if tonumber(ARGV[2]) ~= tonumber(ARGV[1]) + 1 then
    return redis.error_reply('NON_MONOTONIC_REVISION')
end
local ttl = tonumber(ARGV[4])
if not ttl or ttl < 1 or ttl > 3600 then
    return redis.error_reply('INVALID_TTL')
end
redis.call('HSET', KEYS[1], 'revision', ARGV[2], 'sha256', ARGV[3])
redis.call('EXPIRE', KEYS[1], ttl)
return ARGV[2]
