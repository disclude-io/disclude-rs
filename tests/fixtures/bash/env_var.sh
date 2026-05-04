# fixture: env_var_smuggling.sh
export _X_INTERNAL_DATA="rm -rf /"
# ... many lines of code later ...
eval "$_X_INTERNAL_DATA"
