import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import './ManageUsers.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token
        ? { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }
        : { 'Content-Type': 'application/json' };
}

const ROWS_PER_PAGE = 10;

const ManageUsers = () => {
    const navigate = useNavigate();

    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [toast, setToast] = useState({ msg: '', type: '' });
    const [search, setSearch] = useState('');
    const [roleFilter, setRoleFilter] = useState('all');
    const [statusFilter, setStatusFilter] = useState('all');
    const [page, setPage] = useState(1);

    /* Confirm-action modal state */
    const [modal, setModal] = useState({ open: false, type: '', user: null });
    const [modalLoading, setModalLoading] = useState(false);

    /* Current admin id – so we don't show delete/deactivate for ourselves */
    const [adminId, setAdminId] = useState(null);

    useEffect(() => {
        const token = localStorage.getItem('access_token');
        if (!token) { navigate('/login'); return; }
        try {
            const ud = JSON.parse(localStorage.getItem('user_data'));
            if (ud?.user_id) setAdminId(ud.user_id);
        } catch { /* ignore */ }
        fetchUsers();
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    const showToast = useCallback((msg, type = 'success') => {
        setToast({ msg, type });
        setTimeout(() => setToast({ msg: '', type: '' }), 4500);
    }, []);

    /* ---------- API helpers ---------- */
    const fetchUsers = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/auth/admin/users?limit=500`, { headers: authHeaders() });
            if (res.status === 401) { localStorage.removeItem('access_token'); navigate('/login'); return; }
            if (res.status === 403) { setError('Admin privileges required.'); setLoading(false); return; }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setUsers(data);
        } catch (err) {
            console.error(err);
            setError('Failed to load users. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    const toggleActive = async (user) => {
        setModalLoading(true);
        try {
            const res = await fetch(`${API_BASE}/api/auth/admin/users/${user.user_id}`, {
                method: 'PATCH',
                headers: authHeaders(),
                body: JSON.stringify({ is_active: !user.is_active }),
            });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed'); }
            showToast(`User "${user.username}" has been ${user.is_active ? 'deactivated' : 'activated'}.`);
            fetchUsers();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setModalLoading(false);
            setModal({ open: false, type: '', user: null });
        }
    };

    const deleteUser = async (user) => {
        setModalLoading(true);
        try {
            const res = await fetch(`${API_BASE}/api/auth/admin/users/${user.user_id}`, {
                method: 'DELETE',
                headers: authHeaders(),
            });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed'); }
            showToast(`User "${user.username}" has been deleted.`);
            fetchUsers();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setModalLoading(false);
            setModal({ open: false, type: '', user: null });
        }
    };


    /* ---------- Filtering ---------- */
    const filtered = users.filter((u) => {
        if (roleFilter !== 'all' && u.role !== roleFilter) return false;
        if (statusFilter === 'active' && !u.is_active) return false;
        if (statusFilter === 'inactive' && u.is_active) return false;
        if (search) {
            const q = search.toLowerCase();
            return (
                u.username.toLowerCase().includes(q) ||
                u.email.toLowerCase().includes(q) ||
                (u.first_name + ' ' + u.last_name).toLowerCase().includes(q)
            );
        }
        return true;
    });

    /* Reset page when filters/search change */
    useEffect(() => { setPage(1); }, [search, roleFilter, statusFilter]);

    const totalPages = Math.max(1, Math.ceil(filtered.length / ROWS_PER_PAGE));
    const paged = filtered.slice((page - 1) * ROWS_PER_PAGE, page * ROWS_PER_PAGE);

    /* ---------- Helpers ---------- */
    const fmtDate = (d) => {
        if (!d) return '—';
        const dt = new Date(d);
        return dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    };

    const adminName = (() => {
        try {
            const ud = JSON.parse(localStorage.getItem('user_data'));
            if (ud) {
                const n = ((ud.first_name || '') + ' ' + (ud.last_name || '')).trim();
                return n || ud.username || 'Admin';
            }
        } catch { /* ignore */ }
        return 'Admin';
    })();

    /* ---------- Render ---------- */
    return (
        <div className="manage-users-page">
            {/* Header (same style as admin dashboard) */}
            <header className="mu-header">
                <div className="mu-header-left">
                    <h1 className="mu-title">
                        <span className="mu-red">Ran</span><span className="mu-grey">ScanAI</span>
                    </h1>
                    <button className="mu-nav-btn" onClick={() => navigate('/admin-dashboard')}>
                        ← Dashboard
                    </button>
                </div>
                <div className="mu-header-right">
                    <span className="mu-user-info">{adminName} — Admin</span>
                </div>
            </header>

            {/* Toast */}
            {toast.msg && (
                <div className={`mu-toast ${toast.type === 'error' ? 'mu-toast-error' : ''}`}>
                    <span className="mu-toast-icon">{toast.type === 'error' ? '✕' : '✓'}</span>
                    <span>{toast.msg}</span>
                    <button className="mu-toast-close" onClick={() => setToast({ msg: '', type: '' })}>✕</button>
                </div>
            )}

            {/* Content */}
            <div className="mu-content">
                <div className="mu-toolbar">
                    <h2>Manage Users</h2>
                    <div className="mu-toolbar-right">
                        <input
                            type="text"
                            className="mu-search"
                            placeholder="Search username, email, name…"
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                        />
                        <select className="mu-filter" value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
                            <option value="all">All Roles</option>
                            <option value="admin">Admin</option>
                            <option value="user">User</option>
                        </select>
                        <select className="mu-filter" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                            <option value="all">All Status</option>
                            <option value="active">Active</option>
                            <option value="inactive">Inactive</option>
                        </select>
                        <button className="mu-refresh-btn" onClick={fetchUsers} disabled={loading}>
                            🔄 Refresh
                        </button>
                    </div>
                </div>

                {error && <div className="mu-error">{error}</div>}

                {loading ? (
                    <div className="mu-loading">Loading users…</div>
                ) : (
                    <>
                        <div className="mu-summary">
                            Showing <strong>{(page - 1) * ROWS_PER_PAGE + 1}–{Math.min(page * ROWS_PER_PAGE, filtered.length)}</strong> of <strong>{filtered.length}</strong> users
                        </div>

                        <div className="mu-table-wrap">
                            <table className="mu-table">
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Username</th>
                                        <th>Full Name</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>Status</th>
                                        <th>Created</th>
                                        <th>Last Login</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {paged.length === 0 ? (
                                        <tr>
                                            <td colSpan="9" className="mu-empty">No users found.</td>
                                        </tr>
                                    ) : (
                                        paged.map((u, i) => {
                                            const isSelf = u.user_id === adminId;
                                            return (
                                                <tr key={u.user_id} className={!u.is_active ? 'mu-inactive-row' : ''}>
                                                    <td>{(page - 1) * ROWS_PER_PAGE + i + 1}</td>
                                                    <td className="mu-username">{u.username}</td>
                                                    <td>{u.first_name} {u.last_name}</td>
                                                    <td>{u.email}</td>
                                                    <td>
                                                        <span className={`mu-badge mu-badge-${u.role}`}>
                                                            {u.role}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span className={`mu-badge mu-badge-${u.is_active ? 'active' : 'inactive'}`}>
                                                            {u.is_active ? 'Active' : 'Inactive'}
                                                        </span>
                                                    </td>
                                                    <td>{fmtDate(u.created_at)}</td>
                                                    <td>{fmtDate(u.last_login)}</td>
                                                    <td className="mu-actions">
                                                        {isSelf ? (
                                                            <span className="mu-self-label">You</span>
                                                        ) : (
                                                            <>
                                                                <button
                                                                    className={`mu-action-btn ${u.is_active ? 'mu-btn-deactivate' : 'mu-btn-activate'}`}
                                                                    title={u.is_active ? 'Deactivate user' : 'Activate user'}
                                                                    onClick={() => setModal({ open: true, type: 'toggle', user: u })}
                                                                >
                                                                    {u.is_active ? 'Deactivate' : 'Activate'}
                                                                </button>
                                                                <button
                                                                    className="mu-action-btn mu-btn-delete"
                                                                    title="Delete user"
                                                                    onClick={() => setModal({ open: true, type: 'delete', user: u })}
                                                                >
                                                                    Delete
                                                                </button>
                                                            </>
                                                        )}
                                                    </td>
                                                </tr>
                                            );
                                        })
                                    )}
                                </tbody>
                            </table>
                        </div>

                        {/* Pagination */}
                        {totalPages > 1 && (
                            <div className="mu-pagination">
                                <button
                                    className="mu-page-btn"
                                    disabled={page === 1}
                                    onClick={() => setPage(p => p - 1)}
                                >
                                    ← Previous
                                </button>
                                <div className="mu-page-numbers">
                                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(n => (
                                        <button
                                            key={n}
                                            className={`mu-page-num ${n === page ? 'mu-page-active' : ''}`}
                                            onClick={() => setPage(n)}
                                        >
                                            {n}
                                        </button>
                                    ))}
                                </div>
                                <button
                                    className="mu-page-btn"
                                    disabled={page === totalPages}
                                    onClick={() => setPage(p => p + 1)}
                                >
                                    Next →
                                </button>
                            </div>
                        )}
                    </>
                )}
            </div>

            {/* Confirm Modal */}
            {modal.open && (
                <div className="mu-modal-overlay" onClick={() => !modalLoading && setModal({ open: false, type: '', user: null })}>
                    <div className="mu-modal" onClick={(e) => e.stopPropagation()}>
                        {modal.type === 'delete' && (
                            <>
                                <h3>Delete User</h3>
                                <p>Are you sure you want to <span className="mu-bold">permanently delete</span> user <span className="mu-bold">"{modal.user.username}"</span>?</p>
                                <p className="mu-modal-warn">This action cannot be undone. All user data will be removed.</p>
                                <div className="mu-modal-actions">
                                    <button
                                        className="mu-modal-btn mu-modal-cancel"
                                        onClick={() => setModal({ open: false, type: '', user: null })}
                                        disabled={modalLoading}
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        className="mu-modal-btn mu-modal-danger"
                                        onClick={() => deleteUser(modal.user)}
                                        disabled={modalLoading}
                                    >
                                        {modalLoading ? 'Deleting…' : 'Delete User'}
                                    </button>
                                </div>
                            </>
                        )}
                        {modal.type === 'toggle' && (
                            <>
                                <h3>{modal.user.is_active ? 'Deactivate' : 'Activate'} User</h3>
                                <p>
                                    Are you sure you want to <span className="mu-bold">{modal.user.is_active ? 'deactivate' : 'activate'}</span> user <span className="mu-bold">"{modal.user.username}"</span>?
                                </p>
                                {modal.user.is_active && (
                                    <p className="mu-modal-note">The user will not be able to log in until reactivated.</p>
                                )}
                                <div className="mu-modal-actions">
                                    <button
                                        className="mu-modal-btn mu-modal-cancel"
                                        onClick={() => setModal({ open: false, type: '', user: null })}
                                        disabled={modalLoading}
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        className={`mu-modal-btn ${modal.user.is_active ? 'mu-modal-warning' : 'mu-modal-success'}`}
                                        onClick={() => toggleActive(modal.user)}
                                        disabled={modalLoading}
                                    >
                                        {modalLoading ? 'Processing…' : (modal.user.is_active ? 'Deactivate' : 'Activate')}
                                    </button>
                                </div>
                            </>
                        )}

                    </div>
                </div>
            )}
        </div>
    );
};

export default ManageUsers;
