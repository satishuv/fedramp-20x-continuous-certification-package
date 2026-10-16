# Platform implementation guidance (how-to-comply notes)

Each file in this directory is the how-to-comply notes layer for one platform
other than AWS (story MCE-17). The built-in notes in
`validation/scripts/build_notes.py` describe AWS; a file here describes
another platform in the same shape, and the offering profile picks one with
`guidance_platform`:

```json
"guidance_platform": "Google Cloud"
```

Absent or `"AWS"` selects the built-in notes and produces the committed
artifacts byte for byte. Any other value must equal a file's `platform` label.
An unknown label fails the build and lists the platforms available; the notes
layer never substitutes AWS guidance for another platform.

Shipped platforms: `google-cloud.json` (Google Cloud), `azure.json`
(Microsoft Azure), `oci.json` (Oracle Cloud Infrastructure).

## What a platform file carries

| Field | Meaning |
|---|---|
| `platform` | The label every note carries as `guidance_platform`, and the value the profile selects by. |
| `captured` | The date (YYYY-MM-DD) the service names and URLs were captured from the vendor's public documentation. |
| `note` | What the file is and is not: SAS advisory examples, identification only, no determination. |
| `services` | Service name -> the vendor documentation URL it was captured from. Every name must be registered in `THIRD_PARTY_NOTICE.md` and named by at least one note. |
| `family_guidance` | Overrides for FRR families whose built-in text names an AWS service (`CMU`, `IEC`, `MAS`, `VDR` at minimum). The other families use the neutral base text that names no platform. |
| `ksi_guidance` | One note per KSI in the catalog (46), each ending with an `Evidence:` sentence. |

The build copies the selected platform's label into every rule and KSI note,
adds `guidance_references` (the documentation URL of every service a note
names) and records the file, capture date and services table at the top of
`traceability/rule-notes.json` and `traceability/ksi-notes.json`. The SDR
extension, the records store's `fill_guidance` and the DOCX label every copied
note as "SAS guidance, <platform> implementation examples, not the provider's
statement" (MCE-16).

## Wording rules (enforced by `validation/scripts/test_platform_guidance_notes.py`)

- No AWS service name inside another platform's notes.
- No comparative, evaluative or endorsing term from the naming guard's
  lexicon, in any note, whether or not the sentence names a vendor.
- No compliance-determination verb (complies, compliant, satisfies, meets).
  A note says how a provider may evidence an indicator; it never says a
  product meets a requirement. The KSI statement governs.
- No URL inside a note body; the `services` table carries them.
- No em or en dash.
- Service names come from the vendor's public documentation, never from
  memory, and each is registered in `THIRD_PARTY_NOTICE.md` with the owner
  and the one reason it appears. The naming guard
  (`validation/scripts/test_third_party_names.py`) fails the validate job on an
  unregistered name.

## Adding a platform

1. Capture the service names and documentation URLs from the vendor's public
   documentation; record the date in `captured`.
2. Write the file in the shape above. Start from a shipped file; keep the
   neutral KSI notes (training, incident response, policy, recovery
   objectives) and rewrite the ones that name services.
3. Register every service name in `THIRD_PARTY_NOTICE.md` and add it to the
   guard's watchlist, so a sentence naming it is checked for evaluative
   language.
4. Run `python validation/scripts/test_platform_guidance_notes.py` and
   `python validation/scripts/test_third_party_names.py`.

## Removing a platform

Delete its file, its registration row in `THIRD_PARTY_NOTICE.md` and its
watchlist lines in the guard, and clear `guidance_platform` in any profile that
selected it. `python validation/scripts/test_third_party_names.py --inventory`
lists every tracked file that still names it. The built-in AWS notes are
untouched by any of this. The full procedure for withdrawing a third party is
in `THIRD_PARTY_NOTICE.md`, section "Removing a third party".

Everything here is advisory: AWS Security Assurance Services provides advisory
services only, never a compliance determination. Nothing in these files
evaluates, ranks or endorses any product, including AWS products.
