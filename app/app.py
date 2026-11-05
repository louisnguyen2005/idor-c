"""Meko Boutique — mô phỏng website thương mại thời trang và 5 lỗ hổng đào tạo có kiểm soát.

Mỗi đội chạy một tiến trình riêng với TEAM_ID và thư mục dữ liệu riêng. Giao diện người mua
không hiển thị bất kỳ thông tin CTF hoặc flag nào; flag chỉ nằm trong dữ liệu giả lập ở backend
và chỉ lộ ra khi khai thác đúng lỗ hổng tương ứng.
"""
import base64
import functools
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import (Flask, abort, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# Năm nhóm lỗ hổng phục vụ đào tạo.
TASKS = ("sqli", "idor", "upload", "jwt", "backup")
ROOT = Path(__file__).resolve().parent

# Hạng thành viên hợp lệ khi mua sắm. "c-nocturne" là hạng mời riêng, không cấp tự động
# qua giao diện — đây là trọng tâm của thử thách JWT.
PUBLIC_RANKS = {
    "basic": "Thành viên",
    "silver": "Bạc",
    "gold": "Vàng",
}
VIP_RANK = "c-nocturne"


def connect(path):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _new_flag():
    return "FLAG{" + secrets.token_hex(16) + "}"


def create_app(config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        DATA_DIR=Path(os.getenv("MEKO_DATA", "/var/lib/meko-boutique")),
        TEAM_ID=os.getenv("TEAM_ID", "team1"),
        TICK_SECONDS=int(os.getenv("MEKO_TICK_SECONDS", "120")),
        STAFF_PASSWORD=os.getenv("MEKO_STAFF_PASSWORD", ""),
        MAX_CONTENT_LENGTH=256 * 1024,
    )
    app.config.update(config or {})
    data = Path(app.config["DATA_DIR"])
    data.mkdir(parents=True, exist_ok=True)
    app.config["DATA_DIR"] = data

    state_file = data / "state.json"
    app.config["STATE_FILE"] = state_file
    if not state_file.exists():
        state_file.write_text(json.dumps({
            "team": app.config["TEAM_ID"],
            "secret": secrets.token_hex(32),
            "jwt_secret": secrets.token_hex(32),
            "checker_key": app.config.get("CHECKER_KEY", os.getenv("MEKO_CHECKER_KEY", secrets.token_urlsafe(32))),
            "tick": 0,
            "started": time.time(),
            "flags": {t: _new_flag() for t in TASKS},
        }), encoding="utf-8")
        try:
            state_file.chmod(0o600)
        except OSError:
            pass
    state = json.loads(state_file.read_text(encoding="utf-8"))
    if state["team"] != app.config["TEAM_ID"]:
        raise ValueError("DATA_DIR đã thuộc đội khác; hãy dùng vùng dữ liệu riêng cho mỗi đội")
    if app.config["TICK_SECONDS"] < 1:
        raise ValueError("TICK_SECONDS phải lớn hơn 0")

    app.secret_key = state["secret"]
    app.config["CHECKER_KEY"] = state.get("checker_key", "")

    patches_path = data / "patches.json"
    patches = json.loads(patches_path.read_text(encoding="utf-8")) if patches_path.exists() else {}
    app.config["PATCHED"] = {t: bool(patches.get(t, False)) for t in TASKS}

    db_path = data / "shop.sqlite3"
    seed = json.loads((ROOT / "data" / "seed.json").read_text(encoding="utf-8"))
    simulation = data / "simulation"
    designs = simulation / "designs"
    designs.mkdir(parents=True, exist_ok=True)
    # Bản xem trước hợp lệ nằm trong vùng thiết kế công khai.
    (designs / "lookbook.txt").write_text(
        "Gợi ý phối: áo khoác linen cùng phụ kiện tông đất, giày lười trung tính.\n",
        encoding="utf-8")

    def apply_flags(db):
        """Đồng bộ flag hiện hành vào dữ liệu giả lập ở backend."""
        db.execute("UPDATE collection_notes SET secret=?", (state["flags"]["sqli"],))
        db.execute("UPDATE orders SET memo=? WHERE id=9001", (state["flags"]["idor"],))
        (simulation / "private-lookbook.txt").write_text(
            "Lookbook giới hạn — Bộ phối Mùa Thu dành cho stylist nội bộ.\n"
            "Mã lookbook nội bộ: " + state["flags"]["upload"] + "\n",
            encoding="utf-8")

    with connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, name TEXT, email TEXT, address TEXT, rank TEXT DEFAULT 'basic');
            CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, category TEXT, price INTEGER, image TEXT, description TEXT);
            CREATE TABLE IF NOT EXISTS collections(id INTEGER PRIMARY KEY, title TEXT, description TEXT, season TEXT);
            CREATE TABLE IF NOT EXISTS collection_notes(secret TEXT);
            CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, code TEXT, user_id INTEGER, total INTEGER, status TEXT, created TEXT, memo TEXT);
            CREATE TABLE IF NOT EXISTS order_items(order_id INTEGER, product_id INTEGER, quantity INTEGER, price INTEGER);
            CREATE TABLE IF NOT EXISTS outfits(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, manifest TEXT);
            CREATE TABLE IF NOT EXISTS saved_collection(user_id INTEGER, product_id INTEGER, PRIMARY KEY(user_id, product_id));
            CREATE TABLE IF NOT EXISTS coupons(code TEXT PRIMARY KEY, discount INTEGER, note TEXT);
            """
        )
        if not db.execute("SELECT 1 FROM products LIMIT 1").fetchone():
            db.executemany("INSERT INTO products VALUES(?,?,?,?,?,?)",
                           [(p["id"], p["name"], p["category"], p["price"], p["image"], p["description"]) for p in seed["products"]])
            db.executemany("INSERT INTO collections VALUES(?,?,?,?)",
                           [(c["id"], c["title"], c["description"], c["season"]) for c in seed["collections"]])
            db.executemany("INSERT INTO coupons VALUES(?,?,?)",
                           [(c["code"], c["discount"], c["note"]) for c in seed["coupons"]])
            db.execute("INSERT INTO collection_notes VALUES(?)", (state["flags"]["sqli"],))
            # Hồ sơ khách hàng giả lập và một đơn hàng mẫu dùng cho thử thách IDOR.
            db.execute("INSERT INTO customers(id,username,password,name,email,address,rank) VALUES(900,?,?,?,?,?,?)",
                       ("khach-than-thiet", generate_password_hash(secrets.token_urlsafe()),
                        "An Nhiên", "annhien@example.test", "Hồ sơ giả lập · Đà Nẵng", "gold"))
            db.execute("INSERT INTO orders VALUES(9001,'DH-2026-09001',900,1290000,'Đang giao','04/11/2026',?)",
                       (state["flags"]["idor"],))
            db.execute("INSERT INTO order_items VALUES(9001,2,1,1290000)")
        apply_flags(db)

    def refresh_tick():
        elapsed = max(0, int((time.time() - state["started"]) // app.config["TICK_SECONDS"]))
        if not elapsed:
            return
        state["tick"] += elapsed
        state["started"] += elapsed * app.config["TICK_SECONDS"]
        state["flags"] = {t: _new_flag() for t in TASKS}
        state_file.write_text(json.dumps(state), encoding="utf-8")
        with connect(db_path) as db:
            apply_flags(db)

    # Áp dụng các tick đã trôi qua giữa các lần khởi động (restart không reset tick).
    refresh_tick()

    def patched(task):
        return app.config["PATCHED"].get(task, False)

    def current_user(db):
        if not session.get("uid"):
            return None
        return db.execute("SELECT * FROM customers WHERE id=?", (session["uid"],)).fetchone()

    def user_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("uid"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    def staff_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if session.get("staff") is not True:
                return redirect(url_for("staff_login"))
            return fn(*args, **kwargs)
        return wrapped

    def page(title, **kwargs):
        with connect(db_path) as db:
            products = db.execute("SELECT * FROM products ORDER BY id").fetchall()
        return render_template("shop.html", title=title, products=products,
                               customer=session.get("name"),
                               ranks=PUBLIC_RANKS, year=2026, **kwargs)

    def _cart_items(cart):
        with connect(db_path) as db:
            result = []
            for pid, qty in cart.items():
                p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
                if p:
                    result.append(dict(p) | {"quantity": qty})
            return result

    @app.after_request
    def harden(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.before_request
    def rotate_on_tick():
        refresh_tick()

    # ---- Trang mua sắm công khai ----
    @app.get("/health")
    def health():
        with connect(db_path) as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "ok", "service": "meko-boutique", "team": app.config["TEAM_ID"], "tick": state["tick"]}

    @app.get("/")
    def home():
        return page("Trang chủ", hero=True)

    @app.get("/category/<category>")
    def category(category):
        return page(category, category=category)

    @app.get("/search")
    def search():
        return page("Tìm kiếm", q=request.args.get("q", ""))

    @app.get("/product/<int:product_id>")
    def product(product_id):
        with connect(db_path) as db:
            item = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not item:
            abort(404)
        return page(item["name"], item=item)

    @app.get("/collections")
    def collections():
        with connect(db_path) as db:
            rows = db.execute("SELECT * FROM collections ORDER BY id").fetchall()
        return page("Bộ sưu tập", collections=rows)

    @app.get("/collections/search")
    def collection_search():
        # === Thử thách SQL Injection (giới hạn trong catalog bộ sưu tập) ===
        # Nhân viên marketing lọc bộ sưu tập theo tên. Truy vấn nối chuỗi trực tiếp,
        # cho phép UNION sang bảng ghi chú nội bộ collection_notes.
        q = request.args.get("q", "")[:160]
        with connect(db_path) as db:
            if patched("sqli"):
                sql = "SELECT id,title,description FROM collections WHERE title LIKE ?"
                rows = db.execute(sql, ("%" + q + "%",)).fetchall()
            else:
                sql = "SELECT id,title,description FROM collections WHERE title LIKE '%" + q + "%'"
                rows = db.execute(sql).fetchall()
        return page("Tìm bộ sưu tập", collections=rows, q=q, searched=True)

    # ---- Tài khoản khách hàng ----
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return page("Tạo tài khoản", form="register")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[a-zA-Z0-9_-]{3,32}", username) or len(password) < 10:
            return page("Tạo tài khoản", form="register",
                        error="Tên tài khoản từ 3–32 ký tự (chữ, số, _ hoặc -); mật khẩu tối thiểu 10 ký tự."), 400
        try:
            with connect(db_path) as db:
                db.execute("INSERT INTO customers(username,password,name,email,address,rank) VALUES(?,?,?,?,?, 'basic')",
                           (username, generate_password_hash(password),
                            request.form.get("name", username)[:80],
                            request.form.get("email", "")[:120], "Chưa cập nhật"))
        except sqlite3.IntegrityError:
            return page("Tạo tài khoản", form="register", error="Tên tài khoản đã được sử dụng."), 409
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page("Đăng nhập", form="login")
        with connect(db_path) as db:
            user = db.execute("SELECT * FROM customers WHERE username=?",
                              (request.form.get("username", ""),)).fetchone()
        if not user or not check_password_hash(user["password"], request.form.get("password", "")):
            return page("Đăng nhập", form="login", error="Thông tin đăng nhập chưa đúng."), 401
        session.clear()
        session["uid"] = user["id"]
        session["name"] = user["name"]
        # Cấp thẻ hội viên dạng JWT HS256. Hạng lấy từ hồ sơ khách (không bao giờ là c-nocturne).
        rank = user["rank"] if user["rank"] in PUBLIC_RANKS else "basic"
        head = b64(b'{"alg":"HS256","typ":"JWT"}')
        body = b64(json.dumps({"sub": str(user["id"]), "rank": rank, "exp": int(time.time()) + 3600}).encode())
        signing = head + "." + body
        token = signing + "." + b64(hmac.digest(state["jwt_secret"].encode(), signing.encode(), "sha256"))
        response = redirect(request.args.get("next") or url_for("home"))
        response.set_cookie("meko_member", token, httponly=True, samesite="Lax")
        return response

    @app.post("/logout")
    def logout():
        session.clear()
        response = redirect(url_for("home"))
        response.delete_cookie("meko_member")
        return response

    @app.get("/account")
    @user_required
    def account():
        with connect(db_path) as db:
            user = current_user(db)
        return page("Tài khoản", form="account", profile=user)

    @app.post("/account/update")
    @user_required
    def update_account():
        with connect(db_path) as db:
            db.execute("UPDATE customers SET name=?,email=?,address=? WHERE id=?",
                       (request.form.get("name", "")[:80], request.form.get("email", "")[:120],
                        request.form.get("address", "")[:160], session["uid"]))
        session["name"] = request.form.get("name", "")[:80]
        return redirect(url_for("account"))

    @app.get("/account/collection")
    @user_required
    def personal_collection():
        with connect(db_path) as db:
            items = db.execute(
                "SELECT p.* FROM saved_collection s JOIN products p ON p.id=s.product_id WHERE s.user_id=? ORDER BY p.id",
                (session["uid"],)).fetchall()
        return page("Bộ sưu tập cá nhân", personal_items=items)

    @app.post("/account/collection/add/<int:product_id>")
    @user_required
    def save_product(product_id):
        with connect(db_path) as db:
            if not db.execute("SELECT 1 FROM products WHERE id=?", (product_id,)).fetchone():
                abort(404)
            db.execute("INSERT OR IGNORE INTO saved_collection VALUES(?,?)", (session["uid"], product_id))
        return redirect(url_for("personal_collection"))

    # ---- Giỏ hàng và đặt hàng ----
    @app.post("/cart/add/<int:product_id>")
    @user_required
    def cart_add(product_id):
        with connect(db_path) as db:
            item = db.execute("SELECT id FROM products WHERE id=?", (product_id,)).fetchone()
        if not item:
            abort(404)
        cart = session.get("cart", {})
        qty = max(1, min(5, int(request.form.get("quantity", 1) or 1)))
        cart[str(product_id)] = min(20, int(cart.get(str(product_id), 0)) + qty)
        session["cart"] = cart
        return redirect(url_for("cart"))

    @app.get("/cart")
    @user_required
    def cart():
        with connect(db_path) as db:
            coupons = db.execute("SELECT * FROM coupons ORDER BY discount").fetchall()
        return page("Giỏ hàng", cart_items=_cart_items(session.get("cart", {})), coupons=coupons)

    @app.post("/checkout")
    @user_required
    def checkout():
        items = _cart_items(session.get("cart", {}))
        if not items:
            return redirect(url_for("cart"))
        total = sum(x["price"] * x["quantity"] for x in items)
        coupon = request.form.get("coupon", "").upper()
        with connect(db_path) as db:
            discount = db.execute("SELECT discount FROM coupons WHERE code=?", (coupon,)).fetchone()
            if discount:
                total = total * (100 - discount[0]) // 100
            code = "DH-" + str(secrets.randbelow(900000) + 100000)
            cur = db.execute(
                "INSERT INTO orders(code,user_id,total,status,created) VALUES(?,?,?,'Đang xử lý','04/11/2026')",
                (code, session["uid"], total))
            oid = cur.lastrowid
            db.executemany("INSERT INTO order_items VALUES(?,?,?,?)",
                           [(oid, x["id"], x["quantity"], x["price"]) for x in items])
        session["cart"] = {}
        return redirect(url_for("invoice", order_id=oid))

    @app.get("/account/orders")
    @user_required
    def orders():
        with connect(db_path) as db:
            rows = db.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()
        return page("Đơn hàng của tôi", orders=rows)

    @app.get("/account/orders/<int:order_id>/invoice")
    @user_required
    def invoice(order_id):
        # === Thử thách IDOR (hóa đơn đơn hàng) ===
        # Hóa đơn tra theo id đơn đoán được. Khi chưa vá, không kiểm tra chủ sở hữu đơn.
        with connect(db_path) as db:
            order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if not order:
                abort(404)
            if patched("idor") and order["user_id"] != session["uid"]:
                abort(403)
            lines = db.execute(
                "SELECT p.name,oi.quantity,oi.price FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?",
                (order_id,)).fetchall()
        return page("Hóa đơn", invoice=order, invoice_items=lines)

    # ---- Studio phối đồ (upload) ----
    @app.route("/outfits/new", methods=["GET", "POST"])
    @user_required
    def outfit_new():
        if request.method == "GET":
            return page("Tạo bộ phối đồ", form="outfit")
        # === Thử thách Upload (manifest JSON của bộ phối) ===
        # Khách tải lên manifest JSON mô tả bộ phối; trường preview_file trỏ tới một tệp
        # bản xem trước. Khi chưa vá, đường dẫn không bị giới hạn trong designs, nhưng mọi
        # đường dẫn vẫn bị ép phải nằm dưới thư mục simulation — không bao giờ ra hệ thống host.
        upload = request.files.get("manifest")
        if not upload or not upload.filename or Path(upload.filename).suffix.lower() != ".json":
            abort(400)
        raw = upload.read(65537)
        if len(raw) > 65536:
            abort(413)
        try:
            manifest = json.loads(raw)
        except (ValueError, UnicodeError):
            abort(400)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("preview_file"), str):
            abort(400)
        base = (data / "simulation" / "designs").resolve()
        sandbox_root = (data / "simulation").resolve()
        target = (base / manifest.get("preview_file", "")).resolve()
        if patched("upload") and not target.is_relative_to(base):
            abort(400)
        # Rào chắn cứng: dù vá hay chưa, không bao giờ cho đọc ra ngoài vùng simulation giả lập.
        if not target.is_relative_to(sandbox_root) or not target.is_file():
            abort(400)
        with connect(db_path) as db:
            db.execute("INSERT INTO outfits(user_id,name,manifest) VALUES(?,?,?)",
                       (session["uid"], str(manifest.get("name", "Bộ phối mới"))[:80], raw.decode("utf-8")))
        (base / (secrets.token_hex(12) + ".json")).write_bytes(raw)
        return page("Bản phối đã lưu", preview_text=target.read_text(encoding="utf-8"))

    # ---- Đặc quyền hội viên (JWT) ----
    @app.get("/member/benefits")
    @user_required
    def benefits():
        # === Thử thách JWT (xác định hạng thành viên) ===
        # Hạng hội viên được đọc từ thẻ JWT trong cookie meko_member. Khi chưa vá, máy chủ
        # chấp nhận cả token alg=none (không chữ ký), cho phép giả mạo hạng c-nocturne.
        token = request.cookies.get("meko_member", "")
        member = {}
        try:
            head, body, sig = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
            claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            signing = head + "." + body
            expected = b64(hmac.digest(state["jwt_secret"].encode(), signing.encode(), "sha256"))
            valid = ((header.get("alg") == "none" and sig == "" and not patched("jwt"))
                     or (header.get("alg") == "HS256" and hmac.compare_digest(expected, sig)))
            if valid and claims.get("exp", 0) > time.time() and claims.get("sub") == str(session["uid"]):
                member = claims
        except (ValueError, TypeError, UnicodeError, AttributeError):
            pass
        if member.get("rank") not in (VIP_RANK, VIP_RANK + "-plus"):
            return page("Đặc quyền hội viên", vip_locked=True,
                        error="Khu vực ưu đãi riêng dành cho hạng C-Nocturne."), 403
        return page("Đặc quyền C-Nocturne", member_flag=state["flags"]["jwt"])

    # ---- Bản xuất dữ liệu vận hành (backup) ----
    @app.get("/exports/operations.sql")
    def operations_export():
        # === Thử thách Backup (bản xuất dữ liệu vận hành bị công khai) ===
        # Một bản đối soát vận hành bị để công khai qua HTTP (có gợi ý trong robots.txt).
        if patched("backup"):
            abort(404)
        body = ("-- Meko Boutique — ban xuat doi soat van hanh (du lieu gia lap)\n"
                "-- Sinh tu quy trinh backup noi bo, khong danh cho khach hang.\n"
                "INSERT INTO reconciliation_notes(ref,value) VALUES ('ops-key','"
                + state["flags"]["backup"] + "');\n")
        return body, 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/robots.txt")
    def robots():
        lines = ["User-agent: *", "Disallow: /staff", "Disallow: /exports/"]
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    # ---- Khu vực nhân viên ----
    @app.route("/staff/login", methods=["GET", "POST"])
    def staff_login():
        if request.method == "GET":
            return page("Đăng nhập nhân viên", form="staff-login")
        if not app.config["STAFF_PASSWORD"] or not hmac.compare_digest(
                request.form.get("password", ""), app.config["STAFF_PASSWORD"]):
            return page("Đăng nhập nhân viên", form="staff-login", error="Không thể xác thực nhân viên."), 401
        session["staff"] = True
        return redirect(url_for("staff"))

    @app.get("/staff")
    @staff_required
    def staff():
        with connect(db_path) as db:
            all_orders = db.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
        return page("Vận hành cửa hàng", staff=True, orders=all_orders)

    @app.get("/staff/products")
    @staff_required
    def staff_products():
        with connect(db_path) as db:
            items = db.execute("SELECT * FROM products ORDER BY id").fetchall()
        return page("Quản lý sản phẩm", staff=True, staff_products=items)

    @app.post("/staff/products")
    @staff_required
    def staff_add_product():
        name = request.form.get("name", "").strip()[:100]
        price = request.form.get("price", type=int)
        cat = request.form.get("category", "").strip()[:60]
        if not name or not cat or not price or price < 1:
            abort(400)
        with connect(db_path) as db:
            db.execute("INSERT INTO products(name,category,price,image,description) VALUES(?,?,?,'bag.svg',?)",
                       (name, cat, price, request.form.get("description", "")[:240]))
        return redirect(url_for("staff_products"))

    @app.post("/staff/orders/<int:order_id>/status")
    @staff_required
    def staff_update_order(order_id):
        status = request.form.get("status", "")
        if status not in ("Đang xử lý", "Đang giao", "Đã giao", "Đã hủy"):
            abort(400)
        with connect(db_path) as db:
            db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
        return redirect(url_for("staff"))

    # ---- API cho checker ----
    @app.get("/api/collection")
    def checker_state():
        return {"tick": state["tick"], "tasks": list(TASKS), "team": app.config["TEAM_ID"]}

    @app.route("/api/checker/flag/<task>", methods=["GET", "PUT"])
    def checker_flag(task):
        if not app.config["CHECKER_KEY"] or not hmac.compare_digest(
                request.headers.get("X-Checker-Key", ""), app.config["CHECKER_KEY"]):
            abort(403)
        if task not in TASKS:
            abort(404)
        if request.method == "PUT":
            value = request.get_json(silent=True) or {}
            flag = value.get("flag", "")
            if not isinstance(flag, str) or not re.fullmatch(r"FLAG\{[a-f0-9]{32}\}", flag):
                abort(400)
            state["flags"][task] = flag
            state_file.write_text(json.dumps(state), encoding="utf-8")
            with connect(db_path) as db:
                apply_flags(db)
        return {"task": task, "flag": state["flags"][task], "tick": state["tick"]}

    return app


if __name__ == "__main__":
    from waitress import serve
    serve(create_app(), host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8080")))
