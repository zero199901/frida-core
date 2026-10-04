#include <glib.h>
#include <string.h>

/*
 * gum and GLib hardcode the names of their own worker threads ("gum-js-loop",
 * "gmain", "gdbus"), and frida-gum is not forked, so the names cannot be
 * changed at the source. They can still be kept out of the target: the agent
 * links gum and GLib statically, so every thread the target can see under
 * /proc/self/task/<tid>/comm is created by a g_thread_new() call that this
 * link resolves. The linker is told to redirect those calls here with
 * --wrap=g_thread_new / --wrap=g_thread_try_new (see meson.build), and the
 * wrapper hands GLib a neutral name instead.
 *
 * The target's own threads are untouched: its code lives in its own binaries
 * and is not part of this link unit.
 *
 * Note for future edits: a glob like /proc/self/task/*/comm inside a C block
 * comment terminates it. Write <tid> here.
 */

GThread *__real_g_thread_new (const gchar * name, GThreadFunc func, gpointer data);
GThread *__real_g_thread_try_new (const gchar * name, GThreadFunc func, gpointer data,
    GError ** error);

static const gchar *
neutral_thread_name (const gchar * name)
{
  if (name == NULL)
    return NULL;

  /* Same lengths as the originals, so nothing here depends on the comm limit. */
  if (strcmp (name, "gum-js-loop") == 0)
    return "cache-js-loop";
  if (strcmp (name, "gmain") == 0)
    return "cache-gmain";
  if (strcmp (name, "gdbus") == 0)
    return "cache-gdbus";

  return name;
}

GThread *
__wrap_g_thread_new (const gchar * name, GThreadFunc func, gpointer data)
{
  return __real_g_thread_new (neutral_thread_name (name), func, data);
}

GThread *
__wrap_g_thread_try_new (const gchar * name, GThreadFunc func, gpointer data, GError ** error)
{
  return __real_g_thread_try_new (neutral_thread_name (name), func, data, error);
}