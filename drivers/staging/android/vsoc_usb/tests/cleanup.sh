#/bin/sh

while getopts p: opt "$@"
do
    case "${opt}"
    in
    p) modname=${OPTARG}
       sudo rmmod "${modname}"
        ;;
    esac
done
