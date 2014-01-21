#!/bin/bash
rsync -av --exclude=.git --delete ../software/ .
