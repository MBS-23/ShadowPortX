import asyncio

from shadowportx.engines import verification
from shadowportx.engines.verification import ftp, memcached, redis


async def _serve(handler, port):
    return await asyncio.start_server(handler, "127.0.0.1", port)


async def test_registry_includes_new_verifiers():
    names = verification.supported_services()
    for expected in ("redis", "ftp", "smtp", "memcached", "docker", "elasticsearch", "mongodb"):
        assert expected in names


async def test_redis_no_auth_verified():
    async def h(reader, writer):
        await asyncio.wait_for(reader.read(64), timeout=1)
        writer.write(b"# Server\r\nredis_version:6.0.9\r\n")
        await writer.drain()
        writer.close()

    srv = await _serve(h, 8941)
    try:
        res = await redis.verify("127.0.0.1", 8941)
    finally:
        srv.close()
    assert res and res.verified and res.condition == "no-authentication-required"
    assert res.severity.value == "high"


async def test_memcached_no_auth_verified():
    async def h(reader, writer):
        await asyncio.wait_for(reader.read(64), timeout=1)
        writer.write(b"STAT version 1.6.9\r\nSTAT curr_items 0\r\nEND\r\n")
        await writer.drain()
        writer.close()

    srv = await _serve(h, 8942)
    try:
        res = await memcached.verify("127.0.0.1", 8942)
    finally:
        srv.close()
    assert res and res.verified and res.evidence.get("version") == "1.6.9"


async def test_ftp_anonymous_login_verified():
    async def h(reader, writer):
        writer.write(b"220 FTP ready\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=1)  # USER
        writer.write(b"331 need password\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=1)  # PASS
        writer.write(b"230 login successful\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=1)  # QUIT
        writer.close()

    srv = await _serve(h, 8943)
    try:
        res = await ftp.verify("127.0.0.1", 8943)
    finally:
        srv.close()
    assert res and res.condition == "anonymous-login-allowed" and res.severity.value == "high"
