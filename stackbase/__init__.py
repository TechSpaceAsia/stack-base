"""stack-base: reconciles infra/stack.toml into running NixOS servers on Hostinger."""

# Single source of truth for the version sent as part of the User-Agent on
# every outbound API request (see stackbase/http.py::USER_AGENT). Hostinger's
# API sits behind Cloudflare, which 403s urllib's default
# "Python-urllib/3.x" User-Agent -- an explicit, identifying one avoids it.
__version__ = "0.1.1"
