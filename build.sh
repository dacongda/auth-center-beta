#!/bin/bash

cd ./ui

pnpm run install
pnpm run build:naive

cd ..
mv -f ./ui/apps/web-naive/dist/ ./wwwroot