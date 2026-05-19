# p4wnda Reporting Tool

Static GitHub Pages app for building vulnerability reports from structured findings.

Live URL:

```text
https://p4wnda.github.io/reporting-tool/
```

## Purpose

The Pentest Cheatsheet export is useful run context: target info, variables, notes, completed commands, favorites, and copy history. This reporting tool imports that JSON and uses it as supporting evidence while you create proper vulnerability findings.

The tool does not guess vulnerabilities automatically. It helps turn your notes and command evidence into a repeatable report structure.

## Features

- Import `p4wnda.pentest-run.v1` JSON exports from the Pentest Cheatsheet
- Track target metadata and report summary
- Create vulnerability findings with severity, CVSS, affected asset, status, description, impact, evidence, reproduction, remediation, and references
- Reuse imported command history, notes, flags, and credentials as report evidence
- Attach screenshot evidence by pasting images or uploading image files
- Persist work locally in the browser
- Export full report JSON
- Export Markdown report

## Related Tools

- [Project Hub](https://p4wnda.github.io/) - links to all p4wnda GitHub Pages projects.
- [Blog](https://p4wnda.github.io/blog/) - writeups, notes, and lab documentation.
- [Pentest Cheatsheet](https://p4wnda.github.io/pentest/) - exports the run JSON imported by this reporting tool.
- [CTF Checklists](https://p4wnda.github.io/checklists/) - standalone and Active Directory box checklists linked to cheatsheet commands.

## Files

```text
index.html   App shell
styles.css   UI styling
app.js       App behavior and localStorage persistence
```

## Deployment

This repository is intended to be served by GitHub Pages from:

- Branch: `master`
- Folder: `/ (root)`

No build step is required.
