# Call-----Write-up-------DreamHack

Hướng dẫn cách giải challenge Call cho anh em mới chơi Web 

**Author** : Nguyen Kiet 

**Category** : Web Exploitation

# **1. Phân tích**

- Đọc source code 
```
FLAG = open("./flag.txt").read()
superidol = os.urandom(32).hex()

sessions = {}
```
- nhận thấy nội dung của file flag.txt được đọc lên khi server khởi động . Đây là mục tiêu bạn cần lấy 
- superidol : mội chuỗi ngẫu nhiên 32 byte hex được sinh ra khi server khởi động . 
- session = { } : một từ điển lưu trữ session trong bộ nhớ RAM 

```
@app.route('/login', methods=['POST'])  
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if username == 'guest' and password == 'guest':
        session = os.urandom(16).hex()
        sessions[session] = {'username': username, 'role': 'user'}
        
        resp = make_response(jsonify({'success': True, 'message': 'hello'}))
        resp.set_cookie('session', session)
        return resp
    
    return jsonify({'success': False, 'message': 'Login Failed'})
``` 
- Đăng nhập : ở đây có một account username : guest , password : guest đã được tạo sẵn . Nếu đăng nhập đúng , server tạo một chuỗi **session** ID với quyền mặc định là `role : user` và trả về cookie `session`
```
@app.route('/api/flag')
def flag():
    session = request.cookies.get('session')
    
    if session and session in sessions:
        user = sessions[session]

        if user.get('role') == 'admin':
            return jsonify({'flag': FLAG})
    
    return jsonify({'error': 'Permission Denied'}), 403
```
- Lấy flag (`/api/flag`)
- Chức năng : trả về flag nếu người dùng hợp lệ 
- Logic : Kiểm tra cookie `session` 
    - Điều kiện kiên quyết : `user['role']` phải là `'admin'`
    - Nếu bạn chỉ là `guest` (role = 'user') , bạn sẽ bị lỗi 403 Permission Denied
    - Mục tiêu : bạn phải tìm cách đổi `role` từ `user` thành `admin`
```
@app.route('/jsonp/config')
def config():
    callback = request.args.get('callback', 'callback')

    config = {
        'abcdefghijklmnop': {
            'lol': [1, 2, {'b': {
                'proto': [None, None, {'c': {
                    'nestjs': {'d': {
                        'qrstuv': [False, True, {'e': {
                            'iamadmin': {'f': {
                                'secret': [0, {'g': {
                                    'level': {'h': {
                                        'array': [[], [1], {'i': {
                                            'licklol': {'j': {
                                                'nevergonnagiveyouup': [None, {'k': {
                                                    'docker': {'l': {
                                                        '404': [[[[{'m': {
                                                            'dreamhack': {'n': {
                                                                'leak': [1, 2, 3, {'o': {
                                                                    'pwnable': {'p': {
                                                                        'web': [{'q': {
                                                                            'ssrf': {'r': {
                                                                                'ssti': [0, 1, {'s': {
                                                                                    'some': {'t': {
                                                                                        'typescript': [[], {'u': {
                                                                                            'lsal': {'v': {
                                                                                                'cryto': [1, 2, 3, 4, {'w': {
                                                                                                    'file': {'x': {
                                                                                                        'content': [None, False, {'y': {
                                                                                                            'SECRET': superidol
                                                                                                        }}]
                                                                                                    }}
                                                                                                }}]
                                                                                            }}
                                                                                        }}]
                                                                                    }}
                                                                                }}]
                                                                            }}
                                                                        }}]
                                                                    }}
                                                                }}]
                                                            }}
                                                        }}]]]]
                                                    }}
                                                }}]
                                            }}
                                        }}]
                                    }}
                                }}]
                            }}
                        }}]
                    }}
                }}]
            }}]
        }}

    data = f"window.configData = {callback}({json.dumps(config)});"
    
    resp = make_response(data)
    resp.headers['Content-Type'] = 'application/javascript'
    return resp
```
- Đoạn code này mình sẽ giải thích sơ qua : đoạn code đó là một cấu trúc json đa tầng bị làm rối 

- Mục đích : để giấu token ( `superidol` ) dưới 25 tầng dữ liệu hỗn độn nhằm ngăn chặn việc đọc thủ công bằng mắt thường 

- Cấu trúc lồng ghép : sử dụng các Dictionary lồng bên trong các List và lặp lại tiên tục theo bảng chữ cái từ `a` đến `y`
- Dữ liệu rác : chèn thêm các phần tử vô nghĩa vào các List để làm lệch chỉ mục , buộc người giải phải phân tích chính xác cấu trúc để lọc dữ liệu thật 
- Giá trị quan trọng nhất nằm ở đáy : `{'SECRET' : superidol}`

```
@app.route('/api/auth', methods=['POST'])
def auth():
    session = request.cookies.get('session')
    
    if not session or session not in sessions:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json or {}

    try:
        perms = data.get('permissions', {})
        v1 = perms.get('a', {})
        v2 = v1.get('b', {})
        v3 = v2.get('c', {})
        v4 = v3.get('d', {})
        v5 = v4.get('e', {})
        v6 = v5.get('f', {})
        v7 = v6.get('g', {})
        v8 = v7.get('h', {})
        v9 = v8.get('i', {})
        v10 = v9.get('j', {})
        v11 = v10.get('k', {})
        v12 = v11.get('l', {})
        v13 = v12.get('m', {})
        v14 = v13.get('n', {})
        v15 = v14.get('o', {})
        v16 = v15.get('p', {})
        v17 = v16.get('q', {})
        v18 = v17.get('r', {})
        v19 = v18.get('s', {})
        v20 = v19.get('t', {})
        v21 = v20.get('u', {})
        v22 = v21.get('v', {})
        v23 = v22.get('w', {})
        v24 = v23.get('x', {})
        v25 = v24.get('y', {})
        SECRET = v25.get('SECRET', '')
        
        if superidol == SECRET:
            sessions[session]['role'] = 'admin'
            return jsonify({'success': True, 'asdf': ''})
    except:
        pass
    
    return jsonify({'error': 'Invalid permissions'}), 403
```
- nâng quyền (`/api/auth`)
- Chức năng : kiểm tra quyền hạn và nâng cấp user lên admin 
- Logic : 
    - Nhận dữ liệu JSON từ request POST 
    - Nó thực hiện đào sâu và JSON đó theo một đường dẫn cố định : `permissions` -> `a` -> `b` -> `c` -> ... -> `x` -> `y` -> `SECRET`.
    - Điều kiện : Nếu giá trị `SECRET` bạn gửi lên trùng khớp với biến `superidol` của server.
    - Kết quả : `sessions[session]['role'] = 'admin'` . Bạn chính thức trở thành admin.
# **2. Khai thác**

- Hình dung luồng tấn công 

    1. Đăng nhập : gửi POST đến `/login` với `username=guest` và `password=guest` để lấy cookie session 
         - trong Response , server sẽ trả về header : `Seti-Cookie: session=` . Đây là session hợp lệ của bạn ( đang là quyền user ) .
  <img width="603" height="300" alt="image" src="https://github.com/user-attachments/assets/1a3eafa1-9d6c-4c7a-bf1d-02d8dbfd0f5e" />
  
         - copy lại cái `session=e8802377a021376beb14de631545a307`

    2. Truy cập `/jsonp/config` -> để lấy chuỗi `SECRET` ( chính là giá trị `superidol` )
<img width="467" height="59" alt="image" src="https://github.com/user-attachments/assets/60b1ac3a-f154-447e-8f75-1115e0d244b4" />

**Hoặc**

<img width="289" height="127" alt="image" src="https://github.com/user-attachments/assets/f03d1cbf-a1de-4622-b17f-06cedaf727cc" />

**Kết quả**
<img width="1910" height="97" alt="image" src="https://github.com/user-attachments/assets/8f60725e-ae76-4cf0-a273-88676c10f22e" />

**Thấy có dòng : `db58658348f0e96a7574becdf2c2dec697cda6f52b0434ce168e48a573c03412`** : đây chính là giá trị `superidol` được tạo ra ở đầu tiên và bây giờ được gán với `SECRET`



   3. Chuẩn bị Payload : đây là đoạn khó hiểu nhất vì bạn phải hiểu sơ qua code 
        - Lúc đầu source code có dòng `data = request.json or {}` tức là data chính là toàn bộ những gì bạn viết trong request ở phần body
        - chúng ta sẽ gửi đoạn payload này trong burpsuite : 
```
{"permissions":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":{"s":{"t":{"u":{"v":{"w":{"x":{"y":{"SECRET":"5eb7dd65794cc71982036250b3a3907d48cdaffc729477970f3a5abf16a34594"}}}}}}}}}}}}}}}}}}}}}}}}}}}

```
 - Hãy xem code chạy trong từng dòng này : 

    1. `data` : code nhận được nguyên cục json trên 

    2. `perms = data.get('permissions')` : nó lấy cái ruột bên trong key permissions -> lúc này `perms` = `{"a": {"b" : {...}}}` 

    3. `v1 = perms.get('a',{})` : code tìm thấy key `a` trong biến `perms` -> nên nó lấy giá trị của `'a'` -> lúc này `v1` = `{"b" : {...}}`  rồi cứ thế tiếp tục

     4. `SECRET = v25.get('SECRET','')` : Đến cuối cùng thì `v25` là `{"SECRET": "5eb7..."}` nên biến `SECRET` lấy được giá trị "5eb7..."  
    - Bấm send : nếu Response trả về `{"success": true, "asdf": ""}` là đã lên Admin thành công 
4. Lấy flag 
    - Giữ nguyên cái cookie đó 
    - Đổi URL thành /api/flag
    - Đổi method thành GET 
    - Bấm send 
    - Flag sẽ hiện ra trong Response
**Quá đơn giản phải không các bạn. Hãy cho mình 1 star nha 🐧**

  
