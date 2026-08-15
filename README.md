## Module:

Requires [ngx_devel_kit](https://github.com/vision5/ngx_devel_kit) to be added to the build
*before* this module (see `config`).

### Directives:

    Syntax:  headers_save $var name [name ...];
    Default: ——
    Context: http, server, location, if in location

Declares `$var` as a variable that, when evaluated, captures every current request header whose
name matches one of the given `name` patterns — case-insensitive; a pattern ending in `*` matches
by prefix — and has a non-empty value, encoding them into `$var` in an internal binary format.
`$var` is only meant to be consumed by `headers_load`; do not print or otherwise rely on its raw
value.

    Syntax:  headers_load $var;
    Syntax:  headers_load $var key value;
    Default: ——
    Context: http, server, location, if in location

Re-injects the headers captured in `$var` (which must have been produced by `headers_save`) back
into the current request's header list. This runs as part of sending the response (the response
header filter), so the injected headers are *not* visible to anything that already processed the
request by that point — proxying to an upstream, access checks, `Host`-based routing, and so on
all happen earlier and never see them. They only become visible to code that reads request
headers afterwards: chiefly `$http_name` variables (e.g. in `log_format`) and SSI (`ssi on;`)
running in the response body.

With the 3-argument form, `headers_load` additionally acts as a gate on the response: unless the
captured headers include one named `key` (case-insensitive) whose value exactly (case-sensitive)
equals the compiled complex value `value`, the response is replaced with a plain `403 Forbidden`
and the original response body is discarded — not merely relabeled with a different status code.
This also applies, failing closed, when `$var` is empty or wasn't produced by `headers_save` at
all. Note that any upstream already contacted via `proxy_pass` and similar still receives the
request; only what reaches the client is replaced.

A location that doesn't declare its own `headers_load` inherits both the referenced `$var` and,
if present, the `key`/`value` gate from the nearest enclosing location that does. `headers_save`
does not inherit this way: it only takes effect for the exact location it's declared in (or an
ancestor location that ends up handling the request directly), so redeclare it in a child
location if that location's own headers need to be captured.

### Example:

    location / {
        headers_save $token x-internal-token;
        headers_load $token x-internal-token "s3cr3t";
        proxy_pass http://backend;
    }

Requests without `X-Internal-Token: s3cr3t` get a `403 Forbidden` instead of the proxied response.
