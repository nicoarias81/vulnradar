# Context Extension

This layer is optional: it is enabled when there is an asset inventory of your own.

## Goal

Adjust a CVE's Reality according to the criticality of the affected assets.

## Model

1. Load the asset inventory (CSV, API, CMDB, ServiceNow, etc.)
2. Each asset has `criticality` (1.0 – 10.0)
3. Map CVE → assets (by product, CPE, or manually)
4. Compute:
   ```
   Adjusted_Reality = Base_Reality * (criticality / 5.0)
   ```
5. Generate alerts when `Adjusted_Reality > threshold` and the asset is critical

## Usage example

```python
# With an inventory loaded
from core.context import apply_asset_context

base_scores = scoring_agent.run()
adjusted = apply_asset_context(base_scores, inventory)
alert_agent.notify(adjusted)
```

## Assets table (already included in schema.sql)

See `schema.sql` → the `assets` and `cve_assets` tables.
