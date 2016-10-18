# lextab.py. This file automatically created by PLY (version 3.9). Don't edit!
_tabversion   = '3.8'
_lextokens    = set(('DO', 'RETURN', 'CHANGE', 'NOTEQUAL', 'READ', 'ENTER', 'EQUAL', 'WITH', 'APPEND', 'COMMENT', 'SET', 'TOLOWER', 'TO', 'CREATE', 'DEFAULT', 'CONCAT', 'EXIT', 'SPLIT', 'STRING', 'REPLACEWITH', 'DELEGATION', 'AS', 'FOREACH', 'ARROW', 'IN', 'PASSWORD', 'LOCAL', 'ID', 'FILTEREACH', 'WRITE', 'ALL', 'TERMINATE', 'LET', 'DELEGATE', 'DELETE', 'DELEGATOR', 'PRINCIPAL'))
_lexreflags   = 0
_lexliterals  = '=[]{}.,'
_lexstateinfo = {'INITIAL': 'inclusive'}
_lexstatere   = {'INITIAL': [('(?P<t_ID>[a-zA-Z][a-zA-Z_0-9]*)|(?P<t_STRING>\\"[A-Za-z0-9_ ,;\\.?!-]*\\")|(?P<t_COMMENT>//.*)|(?P<t_TERMINATE>\\*\\*\\*)|(?P<t_ARROW>->)|(?P<t_ENTER>\\n)', [None, ('t_ID', 'ID'), ('t_STRING', 'STRING'), ('t_COMMENT', 'COMMENT'), (None, 'TERMINATE'), (None, 'ARROW'), (None, 'ENTER')])]}
_lexstateignore = {'INITIAL': ' \t'}
_lexstateerrorf = {'INITIAL': 't_error'}
_lexstateeoff = {}
