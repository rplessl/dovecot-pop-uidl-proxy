#!/bin/bash
#rsync -av --exclude=.git --delete ../software/ .
rsync -av --exclude=.git ../software/ .

