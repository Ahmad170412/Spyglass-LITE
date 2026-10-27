# Writing a registration recipe

Tier B answers one question per site: **does this address have an account
here?** It is opt-in because some endpoints send mail, and because the
endpoints are undocumented far more often than the vendors would like.

A recipe is data, not code. Adding a site is a JSON object; nothing in the
package needs to change.

```json
{
  "id": "example",
  "name": "Example",
  "url": "https://api.example.com/v1/account/status",
  "method": "POST",
  "headers": { "content-type": "application/json" },
  "payload": { "email": "{email}" },
  "exists_when": { "json_path": "exists", "equals": true },
  "absent_when": { "json_path": "exists", "equals": false },
  "note": "Documented status endpoint."
}
```

```python
import spyglass_lite as sg

sg.email("me@example.com", registrations=True, recipes_path="my-recipes.json")
```

A file may be a list of recipes or `{"recipes": [...]}`.

Recipes can also be passed inline, without a file. Entries are recipe dicts
(schema above) or bare domains/URLs, which are matched against the bundled
recipes by hostname:

```python
sg.email("me@example.com", sites=[
    {
        "name": "Example",
        "url": "https://api.example.com/status?email={email}",
        "exists_when": {"status": 200},
        "absent_when": {"status": 404},
    },
    "api.accounts.firefox.com",   # resolves to the bundled Firefox recipe
])
```

A domain with no recipe is reported as `Registration(exists=None)` with the
reason — "does this email exist here" is site-specific logic, not a URL
pattern, so it is never guessed.

## Keys

| key | required | meaning |
| --- | --- | --- |
| `id` | recommended | Stable identifier, unique within your file. |
| `name` | recommended | Shown in `Registration.site`. Falls back to `id`. |
| `url` | yes | Absolute URL. `{email}` is replaced with the URL-quoted address. |
| `method` | no | `GET` (default), `POST`, `PUT`, `PATCH`, `HEAD`. |
| `headers` | no | Extra request headers, e.g. `content-type` or an app token. |
| `payload` | no | Body for `POST`/`PUT`/`PATCH`. `{email}` is substituted raw (not URL-encoded). Sent as JSON when `content-type` contains `json`, otherwise form-encoded. |
| `params` | no | Query-string parameters appended to `url`. `{email}` is substituted *unencoded* and then URL-encoded by `urlencode`. |
| `exists_when` | one of these | Predicate that means "account exists". |
| `absent_when` | one of these | Predicate that means "no account". |
| `note` | no | Human note about provenance. Not used at runtime. |

## Predicates

Exactly one form per predicate:

| form | matches when |
| --- | --- |
| `{"json_path": "a.b.0", "equals": true}` | The value at the dot path equals the literal. Lists use numeric segments. |
| `{"json_path": "users", "non_empty": true}` | The value is truthy (non-empty list, non-empty object, non-zero). |
| `{"json_path": "users", "empty": true}` | The value is falsy (empty list/object, `null`, `0`, `""`). |
| `{"body_contains": "already registered"}` | Case-insensitive substring of the response body. |
| `{"status": 200}` | Exact HTTP status. |

If neither predicate matches, the result is `Registration(exists=None)` with
evidence `inconclusive (http <status>)`. That is deliberate: a recipe that
cannot tell must not guess, and must not be reported as "no account".

## Rules for a good recipe

1. **Document the endpoint.** Put the vendor documentation URL in `note`. If
   there is no public documentation, say so and expect it to break.
2. **Never copy another project's recipe data.** In particular, do not lift
   from Holehe (GPL-3.0): this package is MIT, and a recipe table is
   copyrightable data. Write the request against the documented endpoint.
3. **Prefer a status or JSON signal to body text.** Body copy changes with
   translations and redesigns; a boolean field is stable.
4. **Do not send mail.** If the endpoint triggers a reset or welcome email,
   do not ship it in the bundled list. A recipe for local use is your call.
5. **Assume the endpoint can be absent.** Return `None`, not `False`, on 401,
   403, 429 or 5xx. The engine already does this when the request fails;
   predicates should not turn an error page into an absence.
6. **Test both branches.** A recipe with only `exists_when` will report every
   unknown as `None`, which is fine but weak. Supply `absent_when` when the
   endpoint makes the distinction.

## Testing a recipe

```python
from spyglass_lite import Spyglass

result = Spyglass().email(
    "me@example.com",
    registrations=True,
    recipes_path="my-recipes.json",
)
for registration in result.registrations:
    print(registration.site, registration.exists, registration.evidence)
```

For offline tests, mock the endpoint with `respx` and assert on
`exists`/`exists is None`; see `tests/test_email.py` for working examples.
