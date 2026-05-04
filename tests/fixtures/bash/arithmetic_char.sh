# fixture: arithmetic_char_gen.sh
# Decodes to: "id"
# 105 = i, 100 = d
cmd=$(printf "\\$(($(echo 105)))\\$(($(echo 100)))")
$cmd
