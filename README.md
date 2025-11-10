# Calculator Instructions


## Table of Contents

* Prerequisites
* Setup
* Running Tests
* Docker
* License

---

## Prerequisites

Make sure you have the following installed:

* Python 3.10+
* pip (Python package manager)
* Docker (optional, for containerized environment)

---

## Setup

1. Clone the repository:

```
git clone https://github.com/BrunoGarofalo/assignment10
cd your-repo
```

2. Create a virtual environment:

```
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

3. Install dependencies:

```
pip install -r requirements.txt
```

## Running Tests

You can run all pytests tests locally with:

```
pytest
```


To run a single test file:

```
pytest tests/integration/test_user.py
```

## Running the model:
- Start Docker with docker compose up or create the containers with docker compose up --build if they are not available yet
- go to localhost:8000 to user the model

## Docker hub repository:
- https://hub.docker.com/repository/docker/legioxi/assignment10/general

