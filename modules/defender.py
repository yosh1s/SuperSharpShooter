#!/usr/bin/python
from random import randint
from copy import deepcopy

def concat_rand(st,pl):
	x = st
	y = []
	while len(x) > 0:
		r = randint(1,4)
		y.append(x[0:r])
		x = x[r:]
	if pl == "js":
		return "'+'".join(y)
	if pl == "vba" or pl == "vbs":
		return '" & "'.join(y)
