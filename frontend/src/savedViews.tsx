import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bookmark, Check, Copy, Settings2, Share2, Star, Trash2, X } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { request } from "./api";
import { Badge, Button, ErrorState, Loading } from "./components";
import type { SavedViewRecord } from "./types";
import { useDialogFocus } from "./useDialogFocus";

type SavedViewsProps<T extends Record<string, unknown>> = {
  page: string;
  state: T;
  builtIn: T;
  apply: (state: T) => void;
  hasExplicitState: boolean;
};

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

function stable(value: Record<string, unknown>) {
  return JSON.stringify(canonical(value));
}

export function SavedViews<T extends Record<string, unknown>>({
  page,
  state,
  builtIn,
  apply,
  hasExplicitState,
}: SavedViewsProps<T>) {
  const [params, setParams] = useSearchParams();
  const [manage, setManage] = useState(false);
  const [editing, setEditing] = useState<"" | "create" | "edit">("");
  const [form, setForm] = useState({ name: "", description: "", visibility: "private" });
  const [error, setError] = useState("");
  const applied = useRef("");
  const queryClient = useQueryClient();
  const requested = params.get("view") ?? "";
  const views = useQuery({
    queryKey: ["saved-views", page],
    queryFn: () => request<{ items: SavedViewRecord[] }>(`/saved-views?page=${page}`),
  });
  const defaults = useQuery({
    queryKey: ["saved-view-defaults"],
    queryFn: () => request<{ items: Array<{ page: string; view: SavedViewRecord }> }>("/saved-views/defaults"),
  });
  const selected = views.data?.items.find((view) => view.id === requested);
  const defaultView = defaults.data?.items.find((item) => item.page === page)?.view;
  const modified = Boolean(selected && selected.compatible && stable(selected.state) !== stable(state));
  const inaccessible = Boolean(
    requested && requested !== "builtin" && views.isSuccess && !selected,
  );

  useEffect(() => {
    if (requested || hasExplicitState || !defaultView?.compatible) return;
    setParams((current) => {
      const next = new URLSearchParams(current);
      next.set("view", defaultView.id);
      return next;
    }, { replace: true });
  }, [defaultView, hasExplicitState, requested, setParams]);

  useEffect(() => {
    if (!selected?.compatible || selected.id === applied.current) return;
    applied.current = selected.id;
    apply(selected.state as T);
  }, [apply, selected]);

  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["saved-views"] }),
      queryClient.invalidateQueries({ queryKey: ["saved-view-defaults"] }),
    ]);
  };
  const create = useMutation({
    mutationFn: () => request<SavedViewRecord>("/saved-views", {
      method: "POST",
      body: JSON.stringify({ ...form, page, state, schema_version: 1 }),
    }),
    onSuccess: async (view) => {
      await refresh();
      setEditing("");
      setParams((current) => { const next = new URLSearchParams(current); next.set("view", view.id); return next; });
    },
    onError: (value) => setError(value instanceof Error ? value.message : "Unable to save view"),
  });
  const update = useMutation({
    mutationFn: (metadata?: { name: string; description: string; visibility: string }) => request<SavedViewRecord>(`/saved-views/${selected?.id}`, {
      method: "PUT",
      body: JSON.stringify({
        name: metadata?.name ?? selected?.name,
        description: metadata?.description ?? selected?.description,
        visibility: metadata?.visibility ?? selected?.visibility,
        state,
        schema_version: 1,
        expected_revision: selected?.revision,
      }),
    }),
    onSuccess: async () => { setEditing(""); await refresh(); },
    onError: (value) => setError(value instanceof Error ? value.message : "Unable to update view"),
  });
  const setDefault = useMutation({
    mutationFn: (viewId: string | null) => request(`/saved-views/defaults/${page}`, {
      method: "PUT", body: JSON.stringify({ view_id: viewId }),
    }),
    onSuccess: refresh,
  });
  const choose = (id: string) => {
    applied.current = "";
    if (id === "builtin") {
      apply(builtIn);
      setParams((current) => { const next = new URLSearchParams(current); next.set("view", "builtin"); return next; });
      return;
    }
    const view = views.data?.items.find((item) => item.id === id);
    if (!view?.compatible) return;
    apply(view.state as T);
    applied.current = view.id;
    setParams((current) => { const next = new URLSearchParams(current); next.set("view", view.id); return next; });
  };
  const openCreate = () => {
    setError("");
    setForm({ name: selected && !selected.can_edit ? `${selected.name} copy` : "", description: "", visibility: "private" });
    setEditing("create");
  };
  const openEdit = () => {
    if (!selected?.can_edit) return;
    setError("");
    setForm({ name: selected.name, description: selected.description, visibility: selected.visibility });
    setEditing("edit");
  };
  const copyLink = async () => {
    if (!selected) return;
    const url = new URL(window.location.href);
    url.search = "";
    url.searchParams.set("view", selected.id);
    await navigator.clipboard.writeText(url.toString());
  };

  return <div className="saved-view-bar" aria-label="Saved views">
    <Bookmark />
    <select aria-label="Saved view" value={selected?.id ?? (requested === "builtin" ? "builtin" : "")} onChange={(event) => choose(event.target.value)}>
      <option value="">Saved views…</option>
      <option value="builtin">Built-in view</option>
      {(views.data?.items ?? []).map((view) => <option value={view.id} disabled={!view.compatible} key={view.id}>{view.name}{view.owner.username ? ` · ${view.owner.username}` : ""}{!view.compatible ? " (incompatible)" : ""}</option>)}
    </select>
    {inaccessible && <span className="saved-view-warning" role="status">Saved view not found or unavailable.</span>}
    {selected && <Badge tone={modified ? "warning" : "neutral"}>{modified ? "Modified" : selected.visibility}</Badge>}
    <Button variant="secondary" onClick={openCreate}>{selected && !selected.can_edit ? "Save as new" : "Save view"}</Button>
    {selected?.can_edit && modified && <Button variant="secondary" onClick={() => update.mutate(undefined)} disabled={update.isPending}><Check /> Update view</Button>}
    {selected?.can_edit && <Button variant="ghost" onClick={openEdit}>Edit details</Button>}
    {selected && <Button variant="ghost" onClick={() => void copyLink()}><Share2 /> Copy link</Button>}
    {selected && <Button variant="ghost" onClick={() => setDefault.mutate(selected.is_default ? null : selected.id)}><Star /> {selected.is_default ? "Remove default" : "Set default"}</Button>}
    <Button variant="ghost" onClick={() => setManage(true)}><Settings2 /> Manage</Button>
    {editing && <ViewEditor form={form} setForm={setForm} error={error} pending={create.isPending || update.isPending} close={() => setEditing("")} save={() => editing === "edit" ? update.mutate(form) : create.mutate()} title={editing === "edit" ? "Edit saved view" : "Save current view"} />}
    {manage && <ManageViews page={page} views={views.data?.items ?? []} loading={views.isLoading} error={views.error as Error | null} close={() => setManage(false)} refresh={refresh} />}
  </div>;
}

function ViewEditor({ form, setForm, error, pending, close, save, title }: {
  form: { name: string; description: string; visibility: string };
  setForm: (value: { name: string; description: string; visibility: string }) => void;
  error: string; pending: boolean; close: () => void; save: () => void; title: string;
}) {
  const dialogRef = useDialogFocus(close);
  return <div className="dialog-backdrop" onMouseDown={close}><section ref={dialogRef} className="saved-view-dialog" role="dialog" aria-modal="true" aria-label="Save view" onMouseDown={(event) => event.stopPropagation()}>
    <header><div><h2>{title}</h2><p>Filters and presentation settings only.</p></div><button className="icon-button" aria-label="Close" onClick={close}><X /></button></header>
    <label>Name<input autoFocus maxLength={128} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
    <label>Description<textarea maxLength={500} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></label>
    <label>Visibility<select value={form.visibility} onChange={(event) => setForm({ ...form, visibility: event.target.value })}><option value="private">Private</option><option value="shared">Shared with the team</option></select></label>
    {error && <p className="form-error">{error}</p>}
    <footer><Button variant="ghost" onClick={close}>Cancel</Button><Button onClick={save} disabled={!form.name.trim() || pending}>{pending ? "Saving…" : "Save view"}</Button></footer>
  </section></div>;
}

function ManageViews({ page, views, loading, error, close, refresh }: {
  page: string; views: SavedViewRecord[]; loading: boolean; error: Error | null;
  close: () => void; refresh: () => Promise<void>;
}) {
  const dialogRef = useDialogFocus(close);
  const mine = views.filter((view) => view.is_owner);
  const shared = views.filter((view) => view.visibility === "shared" && !view.is_owner);
  const administered = views.filter(
    (view) => view.visibility === "private" && !view.is_owner && view.can_edit,
  );
  const remove = async (view: SavedViewRecord) => {
    if (!window.confirm(`Delete saved view “${view.name}”?`)) return;
    await request(`/saved-views/${view.id}`, { method: "DELETE" });
    await refresh();
  };
  const clone = async (view: SavedViewRecord) => {
    const name = window.prompt("Name for the cloned view:", `${view.name} copy`);
    if (!name) return;
    await request(`/saved-views/${view.id}/clone`, { method: "POST", body: JSON.stringify({ name, visibility: "private" }) });
    await refresh();
  };
  return <div className="dialog-backdrop" onMouseDown={close}><section ref={dialogRef} className="saved-view-dialog manage" role="dialog" aria-modal="true" aria-label="Manage saved views" onMouseDown={(event) => event.stopPropagation()}>
    <header><div><h2>Manage saved views</h2><p>{page.replaceAll("_", " ")}</p></div><button className="icon-button" aria-label="Close" onClick={close}><X /></button></header>
    {loading ? <Loading /> : error ? <ErrorState error={error} /> : <>
      <ViewList title="My views" views={mine} action={(view) => <Button variant="ghost" onClick={() => void remove(view)}><Trash2 /> Delete</Button>} />
      <ViewList title="Shared with the team" views={shared} action={(view) => <Button variant="ghost" onClick={() => void clone(view)}><Copy /> Clone</Button>} />
      {administered.length > 0 && <ViewList title="Administered private views" views={administered} action={(view) => <Button variant="ghost" onClick={() => void remove(view)}><Trash2 /> Delete</Button>} />}
    </>}
  </section></div>;
}

function ViewList({ title, views, action }: { title: string; views: SavedViewRecord[]; action: (view: SavedViewRecord) => React.ReactNode }) {
  return <section className="saved-view-list"><h3>{title}</h3>{views.length ? views.map((view) => <div key={view.id}><span><strong>{view.name}</strong><small>{view.description || `${view.visibility} · ${view.owner.username}`}</small></span>{action(view)}</div>) : <p>No views.</p>}</section>;
}
