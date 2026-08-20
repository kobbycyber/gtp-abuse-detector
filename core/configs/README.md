# Core config overrides

The container starts from Open5GS's packaged YAML in `/etc/open5gs/` and the
entrypoint rebinds only what the lab needs (NGAP + GTP-U addresses, PLMN, TAC)
from environment variables in `.env`.

Drop full replacement YAMLs here (e.g. `amf.yaml`, `smf.yaml`, `upf.yaml`) and
mount them over `/etc/open5gs/` in `docker-compose.yml` if you want to pin an
exact configuration for reproducibility in your thesis appendix.
