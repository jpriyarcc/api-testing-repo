# API Testing Repo 

This repository is a **API testing framework** using `pytest`.

## Features
- Organized folder structure
- Environment configs (dev/stage/prod)
- API client wrapper
- Fixtures for authentication
- Reporting (pytest-html, Allure)
- CI/CD friendly

## Setup
```bash
pip install -r requirements.txt
```

## Run Tests
```bash
pytest -m smoke
pytest -m regression
```

## Allure Report
```bash
allure serve reports/allure-results
```
