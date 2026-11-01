# Synthetic lab evidence

All files in this directory are generated examples, not collected host evidence.
Addresses use documentation ranges. Always pass `--synthetic` when replaying
native-format fixtures so findings and future stored metrics carry that label.

Linux suspicious input should produce repeated-failure and subsequent-success
findings. The benign fixture should produce zero findings with default rules.
Synthetic Windows fixtures use one complete Event XML record per line so the
bounded replay reader can isolate malformed records.
