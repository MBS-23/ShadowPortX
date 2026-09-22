from shadowportx.engines.scanner.ports import resolve_ports, service_name_for


def test_explicit_list():
    assert resolve_ports("80,443,8080") == [80, 443, 8080]


def test_range():
    assert resolve_ports("1-10") == list(range(1, 11))


def test_all():
    assert len(resolve_ports("all")) == 65535


def test_top1000_covers_low_ports_and_common():
    ports = resolve_ports("top1000")
    assert 1 in ports and 1024 in ports
    assert 6379 in ports  # redis is a high-value curated port


def test_top100_bounds():
    ports = resolve_ports("top100")
    assert 80 in ports and 443 in ports and 22 in ports
    assert len(ports) <= 100


def test_combined_spec():
    ports = resolve_ports("22,8000-8002")
    assert 22 in ports and 8000 in ports and 8002 in ports


def test_service_name_lookup():
    assert service_name_for(22) == "ssh"
    assert service_name_for(6379) == "redis"
    assert service_name_for(65000) is None
