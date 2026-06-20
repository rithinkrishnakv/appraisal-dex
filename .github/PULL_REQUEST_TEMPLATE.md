## What does this PR do?

<!-- Brief description of the change -->

## Type of Change
- [ ] New skill module
- [ ] Bug fix in existing module
- [ ] New PoC generator
- [ ] Report/output improvement
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Tests

## Module Checklist (if adding a new module)
- [ ] Inherits from `BaseModule`
- [ ] Implements `run(ctx: AnalysisContext) -> List[Finding]`
- [ ] Every finding has a CVSS vector
- [ ] Every S/A-rank finding has at least one PoC
- [ ] Finding ID follows `CATEGORY-SUBCATEGORY-NAME` format
- [ ] Module added to `ALL_MODULES` in `orchestrator.py`
- [ ] Module exported in `appraisal/modules/__init__.py`
- [ ] Tests added in `tests/test_appraisal.py`

## Testing
```bash
python -m pytest tests/ -v
appraisal-dex scan tests/samples/vuln_test.apk --min-rank D
```

## Does this introduce new dependencies?
- [ ] No
- [ ] Yes — listed in `requirements.txt` and `pyproject.toml`

## Screenshots / Terminal Output
<!-- Paste relevant appraisal output or diff -->
