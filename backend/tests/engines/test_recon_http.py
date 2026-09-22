import asyncio

from shadowportx.engines.recon import http_intel


async def test_http_intel_headers_and_tech():
    async def nginx(reader, writer):
        try:
            await asyncio.wait_for(reader.read(2048), timeout=1)
        except Exception:
            pass
        body = b"<html><head><title>Acme</title></head><body>wp-content/themes</body></html>"
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\nContent-Type: text/html\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(nginx, "127.0.0.1", 8921)
    try:
        info = await http_intel.probe("http://127.0.0.1:8921")
    finally:
        server.close()

    assert info is not None
    assert info.server and "nginx" in info.server
    assert info.title == "Acme"
    # All security headers are absent in this response.
    assert info.security_headers["content-security-policy"] is False
    assert info.security_headers["strict-transport-security"] is False
    # Technology detection with evidence.
    names = {t.name for t in info.technologies}
    assert "nginx" in names and "WordPress" in names
    assert all(t.evidence for t in info.technologies)
