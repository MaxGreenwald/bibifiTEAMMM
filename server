#!/usr/bin/python
# usage ./server PORT [PASSWORD]

import copy
import re
import sys
import json 
import socket
import signal
import ply.lex as lex
import ply.yacc as yacc

# receive data in socket until "***" is detected
def recv_end(the_socket):
    total_data=[];data=''
    while True:
        data=the_socket.recv(1024)
        if "***" in data:
            total_data.append(data[:data.find("***")+3])
            break
        total_data.append(data)
    the_socket.settimeout(None)
    return ''.join(total_data)
    
# The server should exit with return code 0 when it receives the SIGTERM signal. 
def sigterm_handler(signum, frame):
    # print (json.dumps({"return_code" : 0}))
    sys.exit(0)    
signal.signal(signal.SIGTERM, sigterm_handler)
 
# command line parameters
port = None
users = {"admin" : "admin", "anyone" : None}
connection = None

try:
    len_argv = len(sys.argv)
    # invalid number of parameters
    if len_argv < 2 or len_argv > 3:
        sys.exit(255)
    # PORT 
    if len_argv >= 2:
        argv_port = sys.argv[1]
        argv_port = str(argv_port)
        # Command line arguments cannot exceed 4096 characters each
        if len(argv_port) <= 4096: 
            # port number starting with 0
            if argv_port[0] == '0':
                sys.exit(255)
            if ' ' in argv_port:    
                sys.exit(255)
            port = int(argv_port) 
            # The port argument must be a number between 1,024 and 65,535 (inclusive). It should be provided in decimal without any leading 0's. Thus 1042 is a valid input number but the octal 052 or hexadecimal 0x2a are not.
            if not (port >= 1024 and port <= 65535):
                sys.exit(255)
        else:
            sys.exit(255)
            
    # [PASSWORD]
    if len_argv == 3:
        admin_password = sys.argv[2]
        # Command line arguments cannot exceed 4096 characters each
        if len(admin_password) <= 4096: # Command line arguments cannot exceed 4096 characters each
            # The password argument, if present, must be a legal string s, per the rules for strings given above, but without the surrounding quotation marks.
            # s indicates a string constant having no more than 65,535 characters surrounded by a pair of double quotes .....
            if re.compile(r'[A-Za-z0-9_ ,;.?!-]*').match(admin_password).group(0) == admin_password:
                users["admin"] = admin_password
            else:
                #print (json.dumps({"return_code" : 255}))
                sys.exit(255)
        else:
            #print (json.dumps({"return_code" : 255}))
            sys.exit(255)
except:
    #print "Unexpected error:", sys.exc_info()
    #print (json.dumps({"return_code" : 255}))
    sys.exit(255)
    
# bind server
sock = None
server_address = None

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('127.0.0.1', port)
    sock.bind(server_address)
    sock.listen(1)
except: 
    # If when starting up the server the port specified by the first argument is taken, the server should exit with code 63.
    #print (json.dumps({"return_code" : 63}))
    #print "Unexpected error:", sys.exc_info()
    sys.exit(63)

# listen for TCP connections
keep_running = True

# token definitions
t_ENTER = r'\n'
t_ARROW = '->'
t_TERMINATE = r'\*\*\*'

reserved = {
 "all"  :  "ALL",
 "append"  :   "APPEND",
 "as"  :   "AS",
 "change"  :   "CHANGE",
 "create"  :   "CREATE",
 "default"  :   "DEFAULT",
 "delegate"  :   "DELEGATE",
 "delegation"  :   "DELEGATION",
 "delegator"  :   "DELEGATOR",
 "delete"  :   "DELETE",
 "do"  :   "DO",
 "exit"  :   "EXIT",
 "foreach"  :   "FOREACH",
 "in"  :   "IN",
 "local"  :   "LOCAL",
 "password"  :   "PASSWORD",
 "principal"  :   "PRINCIPAL",
 "read"  :   "READ",
 "replacewith"  :   "REPLACEWITH",
 "return"  :   "RETURN",
 "set"  :   "SET",
 "to"  :   "TO",
 "write"  :   "WRITE",
 "with" : "WITH",
 "split" : "SPLIT",
 "concat" : "CONCAT",
 "tolower" : "TOLOWER",
 "notequal" : "NOTEQUAL",
 "equal" : "EQUAL",
 "filtereach" : "FILTEREACH",
 "with" : "WITH",
 "let" : "LET",
 "terminate" : "TERMINATE",
}

tokens = ['ENTER','ARROW','STRING', 'COMMENT','ID'] + list(reserved.values())

literals = ['=','[',']','{','}','.',',']
def t_ID(t):
    # identifier having no more than 255 characters
    r'[a-zA-Z][a-zA-Z_0-9]*'
    if t.value in reserved:
        t.type = t.value.upper()
    return t

def t_STRING(t):
    # indicates a string constant having no more than 65,535 characters surrounded by a pair of double quotes
    r'\"[A-Za-z0-9_ ,;\.?!-]*\"'
    if t.value in reserved:
        t.type = t.value.upper()
    return t

def t_COMMENT(t):
    r'//.*'
     
def t_error(t): 
    #print json.dumps({"status" : "FAILED"})
    global connection
    connection.sendall(json.dumps({"status" : "FAILED"}) + "\n") 
    
t_ignore = " \t"

# build lexer
lexer = lex.lex(optimize=1)

def p_prog(p):
    'prog : AS PRINCIPAL ID PASSWORD STRING DO ENTER cmd TERMINATE' 
    #print "prog"
    executeStatements([["prog",p[3],p[5]]] + p[8])

def p_cmd(p):
    '''cmd : exit ENTER
           | return
           | prim_cmd ENTER cmd'''
    if len(p) == 3:
        p[0] = [p[1]] # exit ENTER
    elif len(p) == 2:
        p[0] = [p[1]] # return 
    elif len(p) == 4:
        if isinstance(p[3][0], list):
            p[0] = [p[1]] + p[3] 
        else:
            p[0] = [p[1],p[3]] # prim_cmd 
    #print "cmd"
    # A <cmd> is zero or more primitive commands (described below), each ending with a newline, concluding with either exit or return <expr>.

def p_expr(p):
    '''expr : value 
            | "[" "]"
            | "{" fieldvals "}"'''
    #print "expr"
    if p[1] == "[":
        # print list
        p[0] = []
    elif p[1] == "{":
        # print dict
        p[0] = p[2]
    else: # value
        p[0] = p[1]
    
def p_fieldvals(p):
    '''fieldvals : ID "=" value
                 | ID "=" value "," fieldvals'''
    #print "fieldvals"
    if len(p) == 4:
        p[0] = { p[1] : p[3] }
    elif len(p) == 6: # second rule
        if not p[5].has_key(p[1]):
            p[0] = p[5].copy()
            p[0].update({ p[1] : p[3] })
   
def p_value(p):
    '''value : ID 
             | ID "." ID 
             | STRING'''
    #print "value"
    if len(p) == 4: # id dot id
        p[0] = { p[1] : p[3] , "_dot" : True}
    else:
        p[0] = p[1]
       
def p_prim_cmd(p):
    '''prim_cmd : create_principal 
                | change_password
                | set
                | append
                | local
                | foreach 
                | set_delegation
                | delete_delegation
                | default_delegator
    '''
    #print "prim_cmd"
    p[0] = p[1]
  
def p_create_principal(p):
    'create_principal : CREATE PRINCIPAL ID STRING'
    #print "create_principal"
    p[0] = ["create_principal",p[3],p[4]]

def p_change_password(p):
    'change_password : CHANGE PASSWORD ID STRING'
    #print "change_password"
    p[0] = ["change_password",p[3],p[4]]
    
def p_set(p):
    'set : SET ID "=" expr'
    #print "set"
    p[0] = ["set", p[2], p[4] ]
    
def p_append(p):
    'append : APPEND TO ID WITH expr'
    #print "append"
    p[0] = ["append", p[3], p[5] ]
    
def p_local(p):
    'local : LOCAL ID "=" expr'
    #print "local"
    p[0] = ["local", p[2], p[4] ]
       
def p_foreach(p):
    'foreach : FOREACH ID IN ID REPLACEWITH expr'
    #print "foreach"
    p[0] = ["foreach",p[2], p[4], p[6]]
       
def p_set_delegation(p):
    '''set_delegation : SET DELEGATION tgt ID APPEND ARROW ID   
              | SET DELEGATION tgt ID READ ARROW ID
              | SET DELEGATION tgt ID WRITE ARROW ID
              | SET DELEGATION tgt ID DELEGATE ARROW ID'''
    #print "set_delegation"
    p[0] = ["set_delegation", p[3], p[4], p[5], p[7]]
    
def p_delete_delegation(p):
    '''delete_delegation : DELETE DELEGATION tgt ID APPEND ARROW ID
             | DELETE DELEGATION tgt ID READ ARROW ID
             | DELETE DELEGATION tgt ID WRITE ARROW ID
             | DELETE DELEGATION tgt ID DELEGATE ARROW ID'''
    #print "delete_delegation"
    p[0] = ["delete_delegation", p[3], p[4], p[5], p[7]]
    
def p_default_delegator(p):
    'default_delegator : DEFAULT DELEGATOR "=" ID'
    #print "default_delegator"
    p[0] = ["default_delegator", p[4]]
        
def p_exit(p):
    'exit : EXIT'
    #print "exit"
    p[0] = ["exit"]
        
def p_return(p):
    'return : RETURN expr ENTER'
    #print "return"
    p[0] = ["return", p[2]]

def p_tgt(p):
    '''tgt : ALL 
           | ID'''
    #print "tgt"
    p[0] = p[1]
    
def p_error(p):
    #print "error parser"
    #print json.dumps({"status" : "FAILED"})
    global connection
    connection.sendall(json.dumps({"status" : "FAILED"}) + "\n") 
  
# yacc
parser = yacc.yacc(debug=False, optimize=1)

# maintain server status
data = dict()
program_output = []

def check_security_state(var_in, tgt, right, p):
    if p == "admin":
        return True
    else:
        tgt_rights = var_in[tgt][right]
        for tgt_right in tgt_rights:
            if "_" in tgt_right :
                to_user, from_user = tgt_right.split("_")
            else:
                to_user = tgt_right
            if to_user == "anyone" or to_user == p:
                return True
        return False
    
def eval_expr(program_users, program_data, local_variables, expr, principal, is_recursive):
    if isinstance(expr, str):
        if expr[0] == '"' and expr[-1] == '"': # expr s (string)
            if len(expr) > 65535+2:
                return [-1, json.dumps({"status" : "FAILED"})]
            return [0, expr]                
        else: # expr x (another variable)
            var_in = None # determine if expr is in program_data or local_variables
            
            # Fails if x does not exist
            if program_data.has_key(expr):
                var_in = program_data
            elif local_variables.has_key(expr):
                var_in = local_variables
            else:
                return [-1, json.dumps({"status" : "FAILED"})]
            
            # Security violation if the current principal does not have read permission on x.
            if not check_security_state(var_in, expr, "read", principal): 
                return [-1, json.dumps({"status" : "DENIED"})]
             
            # Returns the current value of variable x.
            return eval_expr(program_users, program_data, local_variables, var_in[expr]["value"], principal, False)
    elif isinstance(expr, dict):
        expr2 = copy.deepcopy(expr)
        if not (expr2.has_key("_dot")): # { x1 = <value>, x2 = <value>, ... , xn = <value> }
            if not is_recursive:
                for x in expr2.keys():
                    
                    return_code, evaluated_expr = eval_expr(program_users, program_data, local_variables, expr2[x], principal, True)
                    if return_code == -1:
                        return [-1,evaluated_expr] # in this case evaluated_expr contains status FAILED or DENIEND
                    else:
                        expr2[x] = evaluated_expr
                return [0,expr2]
            else:
                return [-1, json.dumps({"status" : "FAILED"})] # evaluating dictionary as value of another dictionary   
        else: # expr x.y    
            var_in = None # determine if expr is in program_data or local_variables
                
            x = expr2.keys()[0]
            y = expr2[x] 
                
            # Fails if x does not exist
            if program_data.has_key(x):
                var_in = program_data
            elif local_variables.has_key(x):
                var_in = local_variables
            else:
                return [-1, json.dumps({"status" : "FAILED"})]
            
            # Security violation if the current principal does not have read permission on x.
            if not check_security_state(var_in, x, "read", principal):
                return [-1, json.dumps({"status" : "DENIED"})]
            return [0,var_in[x]["value"][y]]
        
    elif isinstance(expr, list): # list
        expr2 = copy.deepcopy(expr)
        return [0,expr2]
    
# execute program
def executeStatements(stmt_list):
    try:
        #print "Executing statements"
        
        global data
        global users
        global keep_running
            
        # setting variables for each program
        principal = None
        return_code = 0
        program_output = []
        #program_data = dict(data)
        program_data = copy.deepcopy(data)
        #program_users = dict(users)
        program_users = copy.deepcopy(users)
        program_default_delegator = "anyone"
        local_variables = dict()
        
        for stmt in stmt_list:
            #print "program data " , program_data
            #print stmt
            
            if stmt[0] == "prog":
                # e.g. ['prog', 'admin', '"admin"']
                principal = stmt[1]
                password = stmt[2][1:-1] # remove quotes
                
                # Fails if principal p does not exist.
                if not users.has_key(principal):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break
                
                # Security violation if the password s is not p's password.
                if users[principal] != password:
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break
                
                # Otherwise, the server terminates the connection after running <cmd> under the authority of principal p.
            elif stmt[0] == "exit":
                # The server should only halt if it is specifically directed to exit by the administrator
                # This command is only allowed if the current principal is admin; otherwise it is a security violation
                if principal == "admin":
                    program_output += [json.dumps({"status" : "EXITING"})]
                    keep_running = False
                else:
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break
            elif stmt[0] == "return":
                return_code, evaluated_expr = eval_expr(program_users, program_data, local_variables, stmt[1], principal, False)

                if return_code == -1:
                    program_output = evaluated_expr # this variable contains json dumped status
                    break
                
                #if len(evaluated_expr) > 1: # remove quotes if string
                #    if evaluated_expr[0] == '"' and evaluated_expr[-1] == '"':
                #        evaluated_expr = evaluated_expr[1:-1]
                
                program_output += [json.dumps({"status" : "RETURNING", "output": evaluated_expr }).replace('\\"','')]
            elif stmt[0] == "create_principal":
                p = stmt[1]
                s = stmt[2][1:-1] # remove quotes
                
                # Failure conditions
                
                # Security violation if the current principal is not admin. 
                if principal != "admin":
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break
                
                # Fails if p already exists as a principal.
                if program_users.has_key(p):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break

                # Successful status code: CREATE_PRINCIPAL
                program_users[p] = s
                
                # if default delegator is set: when a principal q is created, the system automatically delegates all from p to q
                if program_default_delegator != "anyone":
                    for var in program_data:  
                        for right in ["read","write","append","delegate"]:
                            tgt_rights = program_data[var][right]
                            for tgt_right in tgt_rights:
                                if "_" in tgt_right :
                                    to_user, from_user = tgt_right.split("_")
                                else:
                                    to_user = tgt_right
                                if to_user == program_default_delegator:
                                    program_data[var][right].append(p + "_" + program_default_delegator) 
                    
                program_output += [json.dumps({"status" : "CREATE_PRINCIPAL"})]
            elif stmt[0] == "change_password":
                p = stmt[1] 
                s = stmt[2][1:-1] # remove quotes
                
                # Failure conditions:
                
                # Security violation if the current principal is not admin. 
                if principal != "admin" and principal != p:
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break
                
                # Fails if principal p does not exist.                
                if not program_users.has_key(p):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break
                                
                # Successful status code: CHANGE_PASSWORD
                program_users[p] = s
                program_output += [json.dumps({"status" : "CHANGE_PASSWORD"})]
            elif stmt[0] == "set":
                x = stmt[1]
                expr = stmt[2]
                
                # Failure conditions:
                
                # Security violation if the current principal does not have write permission on x.
                if program_data.has_key(x):
                    if not check_security_state(program_data, x, "write", principal):
                        return_code = -1
                        program_output = json.dumps({"status" : "DENIED"})
                        break

                # If x does not exist this command creates it.
                # If x is created by this command, and the current principal is not admin, then the current principal is delegated read, write, append, and delegate rights from the admin on x (equivalent to executing set delegation x admin read -> p and set delegation x admin write -> p, etc. where p is the current principal).
                return_code,evaluated_expr = eval_expr(program_users, program_data, local_variables, expr, principal,False)
                
                if return_code == -1: # something went wrong
                    program_output = evaluated_expr # this variable contains json dumped status
                    break

                if principal == "admin":
                    program_data[x] = {"value" : evaluated_expr, "read" : [], "write" : [], "append" : [], "delegate" : []}
                else:
                    program_data[x] = {"value" : evaluated_expr, "read" : [principal + "_admin"], "write" : [principal + "_admin"], "append" : [principal + "_admin"], "delegate" : [principal + "_admin"]}
                
                # Successful status code: SET
                program_output += [json.dumps({"status" : "SET"})]
            elif stmt[0] == "append":
                x = stmt[1]
                expr = stmt[2]
                
                # Failure conditions:
                
                # Fails if x is not defined or is not a list.
                var_in = None # determine if x is in program_data or local_variables
                if program_data.has_key(x):
                    var_in = program_data
                elif local_variables.has_key(x):
                    var_in = local_variables
                else:
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})
                    break
                
                if not isinstance(var_in[x]["value"], list):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})
                    break
                
                # Security violation if the current principal does not have either write or append permission on x.
                if not check_security_state(var_in, x, "append", principal):
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break
                
                return_code,evaluated_expr = eval_expr(program_users, program_data, local_variables, expr, principal,False)
                
                if return_code == -1: # something went wrong
                    program_output = evaluated_expr # this variable contains json dumped status
                    break
                
                # Successful status code: APPEND
                if isinstance(evaluated_expr, list): #if <expr> evaluates to a list, then it is concatenated to (the end of) x
                    var_in[x]["value"] += evaluated_expr
                else: # If <expr> evaluates to a record or a string, it is added to the end of x
                    var_in[x]["value"].append(evaluated_expr)
                
                program_output += [json.dumps({"status" : "APPEND"})]                
            elif stmt[0] == "local":
                x = stmt[1]
                expr = stmt[2]
                
                # Failure conditions:
                
                #  Fails if x is already defined as a local or global variable 
                if program_data.has_key(x) or local_variables.has_key(x):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})
                    break

                # If x does not exist this command creates it.
                # If x is created by this command, and the current principal is not admin, then the current principal is delegated read, write, append, and delegate rights from the admin on x (equivalent to executing set delegation x admin read -> p and set delegation x admin write -> p, etc. where p is the current principal).
                if principal == "admin":
                    local_variables[x] = {"value" : expr, "read" : [], "write" : [], "append" : [], "delegate" : []}
                else:
                    local_variables[x] = {"value" : expr, "read" : [principal + "_admin"], "write" : [principal + "_admin"], "append" : [principal + "_admin"], "delegate" : [principal + "_admin"]}

                # Successful status code: SET
                program_output += [json.dumps({"status" : "LOCAL"})]
                
            elif stmt[0] == "foreach":
                # foreach y in x replacewith <expr>
                y = stmt[1]
                x = stmt[2]
                expr = stmt[3]
                
                # Failure conditions:
                
                # Fails if x is not a list or if y is already defined as a local or global variable.
                var_in = None # determine if x is in program_data or local_variables
                if program_data.has_key(x):
                    var_in = program_data
                elif local_variables.has_key(x):
                    var_in = local_variables
                else:
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})
                    break
                
                # evaluate x to check if type(x) is list
                return_code,evaluated_x = eval_expr(program_users, program_data, local_variables, x, principal,False)
                    
                if return_code == -1: # something went wrong
                    program_output = evaluated_x # this variable contains json dumped status
                    break
                
                if not isinstance(evaluated_x, list) or program_data.has_key(y) or local_variables.has_key(y):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})
                    break 
                 
                # Security violation if the current principal does not have read and write permission on x.
                if not check_security_state(var_in, x, "append", principal) or not check_security_state(var_in, x, "write", principal):
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break
                
                return_code = 0
                
                need_expr_eval = True
                evaluated_expr = None
                  
                if isinstance(expr, dict):
                    if len(expr.keys()) == 2:
                        if expr.has_key("_dot"):
                            if expr.keys()[0] == y:
                                # expr: field of y
                                need_expr_eval = False
                         
                if need_expr_eval:
                    # if expr includes y
                    if isinstance(expr, dict):
                        for k in expr:
                            if expr[k] == y:
                                expr[k] = '"###same###"'
                
                    # If any execution of <expr> fails or has a security violation, then entire foreach does.    
                    return_code,evaluated_expr = eval_expr(program_users, program_data, local_variables, expr, principal,False)
                    
                    if return_code == -1: # something went wrong
                        program_output = evaluated_expr # this variable contains json dumped status
                        break
                
                record_list = evaluated_x                
                new_record_list = []
                
                for record in record_list:
                    if return_code == -1: # an error has occured, and for must be stopped
                        break
                    else:
                        if isinstance(expr, dict):
                            if not need_expr_eval:
                                if record.has_key(expr[y]):
                                    # expr y.field
                                    new_record_list.append(record[expr[y]])
                                else:
                                    # expr y.field, but y has no field
                                    return_code = -1
                                    program_output = json.dumps({"status" : "FAILED"})
                                    break
                            else:
                                # replace y if y in dict
                                #c = dict(evaluated_expr)
                                c = copy.deepcopy(evaluated_expr)
                                for k in c:
                                    if c[k] == '"###same###"':
                                        c[k] = record 
                                new_record_list.append(c)
                        else:
                            new_record_list.append(evaluated_expr)
                               
                var_in[x]["value"] = new_record_list
                
                # Successful status code: FOREACH
                program_output += [json.dumps({"status" : "FOREACH"})]
            elif stmt[0] == "set_delegation":
                tgt = stmt[1]
                q = stmt[2]
                right = stmt[3]
                p = stmt[4]
                
                # Failure conditions:
                # Fails if either p or q does not exist.
                if not (program_users.has_key(p) and program_users.has_key(q)):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break
                
                # Fails if x does not exist or if it is a local variable, if <right> is a variable x.
                if tgt != "all":
                    if not program_data.has_key(tgt):
                        return_code = -1
                        program_output = json.dumps({"status" : "FAILED"})   
                        break
                
                # Security violation unless the current principal is admin or q  
                if not (principal == "admin" or principal == q):
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break               
  
                # Security violation if the principal is q and <tgt> is the variable x, then q must have delegate permissions on x
                if tgt == "all":
                    for var in program_data:
                        if check_security_state(program_data, var, "delegate", principal):  
                            if p != "admin":
                                if p + "_" + q not in var[right]: 
                                    var[right].append(p + "_" + q) 
                else:
                    if check_security_state(program_data, tgt, "delegate", principal):
                        if p != "admin":  
                            #print program_data[tgt][right]
                            program_data[tgt][right].append(p + "_" + q)
                    else:
                        return_code = -1
                        program_output = json.dumps({"status" : "DENIED"})
                        break
                # Successful status code: SET_DELEGATION
                program_output += [json.dumps({"status" : "SET_DELEGATION"})]
            elif stmt[0] == "delete_delegation":
                tgt = stmt[1]
                q = stmt[2]
                right = stmt[3]
                p = stmt[4]
                
                # Failure conditions:
                # Fails if either p or q does not exist.
                if not (program_users.has_key(p) and program_users.has_key(q)):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break
                
                # Security violation unless the current principal is admin or q  
                if not (principal == "admin" or principal == q or principal == p):
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})
                    break         
                
                # Fails if x does not exist or if it is a local variable, if <right> is a variable x.
                if tgt != "all" and not program_data.has_key(tgt):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break
                
                # Security violation if the principal is q and <tgt> is the variable x, then q must have delegate permissions on x
                if tgt == "all":
                    for var in program_data:  
                        if p + "_" + q in var[right]:
                            if principal == "admin" or principal == p:
                                var[right].remove(p + "_" + q)
                            elif principal == q:
                                if check_security_state(program_data, var, "delegate", q): 
                                    var[right].remove(p + "_" + q) 
                else:
                    if p + "_" + q in program_data[tgt][right]:
                        if principal == "admin" or principal == "p":
                            program_data[tgt][right].remove(p + "_" + q)
                        elif check_security_state(program_data, tgt, "delegate", q): 
                            program_data[tgt][right].remove(p + "_" + q)
                        else:                    
                            return_code = -1
                            program_output = json.dumps({"status" : "DENIED"})
                            break
                
                # Successful status code: DELETE_DELEGATION       
                program_output += [json.dumps({"status" : "DELETE_DELEGATION"})]                
            elif stmt[0] == "default_delegator":
                p = stmt[1]

                # Failure conditions:
                # Security violation if the current principal is not admin.
                if principal != "admin":
                    return_code = -1
                    program_output = json.dumps({"status" : "DENIED"})   
                    break
                # Fails if p does not exist.
                if not program_users.has_key(p):
                    return_code = -1
                    program_output = json.dumps({"status" : "FAILED"})   
                    break
                
                # Successful status code: DEFAULT_DELEGATOR
                program_default_delegator = p
                
                # Successful status code: DEFAULT_DELEGATOR 
                program_output += [json.dumps({"status" : "DEFAULT_DELEGATOR"})]       
                
        # the program succeeds
        # In this case, the client will receive outputs from running the program, and the server state is updated appropriately.
        if return_code == 0:
            data = program_data
            users = program_users
            #for po in program_output:
            #    print po
            program_output = "\n".join(program_output) 
        else:
            # failed or denied
            #print program_output
            pass
        
    except:
        #print "Unexpected error:", sys.exc_info() # DELETE
        #print json.dumps({"status" : "FAILED"})
        program_output = json.dumps({"status" : "FAILED"})
    
    global connection
    connection.sendall(program_output + "\n")   
 
while keep_running:
    try:        
        connection, client_address = sock.accept()
        connection.settimeout(30)
        
        source_code = recv_end(connection).strip()
        
        # All programs consist of at most 1,000,000 ASCII (8-byte) characters (not a wide character set, like unicode); non-compliant programs result in failure.
        if (not isinstance(source_code, str)) or len(source_code) > 1000000:
            #print json.dumps({"status" : "FAILED"})
            connection.sendall(json.dumps({"status" : "FAILED"}) + "\n") 
        else:
            # remove comments
            new_source_code = []
            
            lines = source_code.split("\n")
            for line in lines:
                line = line.strip()
                pos = line.find("//")
                if pos != -1:
                    if line[:pos].strip() == "":
                        pass
                    else:
                        new_source_code.append(line[:pos] + "\n")
                else:
                    new_source_code.append(line + "\n")
            source_code = ("".join(new_source_code))
              
            # parsing and executing programs
            parser.parse(source_code.strip())
        
        connection.close()
    except socket.timeout:
        #print json.dumps({"status" : "TIMEOUT"})
        connection.sendall(json.dumps({"status" : "TIMEOUT"}) + "\n")
        connection.close()
    except SystemExit as e:
        sys.exit(e)
    except:
        print "Unexpected error:", sys.exc_info() # DELETE
        sys.exit(255)