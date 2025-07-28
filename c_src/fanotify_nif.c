#include <erl_nif.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/fanotify.h>
#include <unistd.h>

ERL_NIF_TERM atom_nil;
ERL_NIF_TERM atom_error;

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    atom_nil = enif_make_atom(env, "nil");
    atom_error = enif_make_atom(env, "error");

    return 0;
}

static ERL_NIF_TERM new_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 0) {
        return enif_make_badarg(env);
    }

    int fanotify_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME, 0);
    if (fanotify_fd == -1) {
        return enif_make_tuple2(env, atom_error, enif_make_int(env, errno));
    }

    return enif_make_int(env, fanotify_fd);
}

static ERL_NIF_TERM mark_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 4) {
        return enif_make_badarg(env);
    }

    int fanotify_fd;
    if (!enif_get_int(env, argv[0], &fanotify_fd)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary path;
    if (!enif_inspect_binary(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    unsigned int fanotify_flags;
    if (!enif_get_uint(env, argv[2], &fanotify_flags)) {
        return enif_make_badarg(env);
    }

    uint64_t fanotify_mask;
    if (!enif_get_uint64(env, argv[3], &fanotify_mask)) {
        return enif_make_badarg(env);
    }

    int ret = fanotify_mark(fanotify_fd, fanotify_flags, fanotify_mask, 0, (char*)path.data);
    if (ret == -1) {
        return enif_make_tuple2(env, atom_error, enif_make_int(env, errno));
    }

    return atom_nil;
}

static ERL_NIF_TERM read_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    int fanotify_fd;
    if (!enif_get_int(env, argv[0], &fanotify_fd)) {
        return enif_make_badarg(env);
    }

    int count;
    if (!enif_get_int(env, argv[1], &count)) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM event;
    unsigned char* ev_bytes = enif_make_new_binary(env, count, &event);

    int read_bytes = read(fanotify_fd, ev_bytes, count);
    if (read_bytes == -1) {
        return enif_make_tuple2(env, atom_error, enif_make_int(env, errno));
    }

    return enif_make_tuple2(env, enif_make_int(env, read_bytes), event);
}

static ERL_NIF_TERM close_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    int fanotify_fd;
    if (!enif_get_int(env, argv[0], &fanotify_fd)) {
        return enif_make_badarg(env);
    }

    int ret = close(fanotify_fd);
    if (ret == -1) {
        return enif_make_tuple2(env, atom_error, enif_make_int(env, errno));
    }

    return atom_nil;
}

static ErlNifFunc nif_funcs[] = {
    {"new_nif", 0, new_nif},
    {"mark_nif", 4, mark_nif},
    {"read_nif", 2, read_nif, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"close_nif", 1, close_nif},
};

ERL_NIF_INIT(fanotify, nif_funcs, load, NULL, NULL, NULL)
