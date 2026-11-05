"""Per-tool-group deep command catalogs. Each module defines EXTRA_ACTIONS: dict[str, tuple[Action, ...]]
mapping a Tool.name to additional graded Actions, folded into TOOLS by dogpark.tools._merge_extras."""
