#!/usr/bin/env bash

# Script used to execute a puncover_riscv release:
#
# 1. Update the version in the code
# 2. Commit the change
# 3. Tag the commit
# 4. Push the commit and the tag
# 5. Build the package
# 6. Upload the package to PyPI
# 7. Create a release on GitHub
# 8. Upload the package to the release on GitHub
#
# It can be run for example like so:
#
# PUNCOVER_RISCV_VERSION=0.2.3 ./release.sh

set -euo pipefail

if [[ -z "${PUNCOVER_RISCV_VERSION:-}" ]]; then
    echo "PUNCOVER_RISCV_VERSION must be set"
    exit 1
fi

# check if tag already exists
if git rev-parse -q --verify "refs/tags/${PUNCOVER_RISCV_VERSION}"; then
    echo "Tag ${PUNCOVER_RISCV_VERSION} already exists"
    exit 1
fi

PUNCOVER_RISCV_VERSION_COMMA_DELIMITED=$(echo ${PUNCOVER_RISCV_VERSION} | sed 's/\./, /g')

if grep -q "${PUNCOVER_RISCV_VERSION_COMMA_DELIMITED}" puncover_riscv/version.py; then
    echo "Version ${PUNCOVER_RISCV_VERSION} already set in puncover_riscv/version.py"
    exit 1
fi

# little sed magic to update the version in the code
sed -i -r 's/(.*__version_info__ = )\(.*\)/\1\('"${PUNCOVER_RISCV_VERSION_COMMA_DELIMITED}"'\)/g' puncover_riscv/version.py
git add . && git commit -m "Bump version to ${PUNCOVER_RISCV_VERSION}"
git tag -a {-m=,}${PUNCOVER_RISCV_VERSION}
python3 setup.py sdist bdist_wheel

read -p "Ready to push to GitHub and publish to PyPi? " -n 1 -r
echo    # move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    git push && git push --tags
    twine upload dist/*
    gh release create --generate-notes ${PUNCOVER_RISCV_VERSION}
    gh release upload ${PUNCOVER_RISCV_VERSION} dist/*
fi
