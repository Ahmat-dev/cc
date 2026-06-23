<?php
use Slim\Factory\AppFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();
$app->addBodyParsingMiddleware();

// CORS Middleware (Allows your Vue frontend to communicate with this API)
$app->add(function (Request $request, $handler) {
    $response = $handler->handle($request);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
});

// Preflight OPTIONS handler
$app->options('/{routes:.+}', function ($request, $response) { return $response; });

// Database Connection Helper
function getDB() {
    $host = $_ENV['DB_HOST'] ?? getenv('DB_HOST');
    $port = $_ENV['DB_PORT'] ?? getenv('DB_PORT') ?: 3306;
    $db   = $_ENV['DB_NAME'] ?? getenv('DB_NAME');
    $user = $_ENV['DB_USER'] ?? getenv('DB_USER');
    $pass = $_ENV['DB_PASS'] ?? getenv('DB_PASS');
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
    return $pdo;
}

// JWT Authentication Middleware
$authMiddleware = function (Request $request, $handler) {
    $header = $request->getHeaderLine('Authorization');
    if (!$header || !preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
    try {
        $secret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET');
        $decoded = JWT::decode($matches[1], new Key($secret, 'HS256'));
        $request = $request->withAttribute('user', (array)$decoded);
    } catch (Exception $e) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode(['error' => 'Invalid Token']));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
    return $handler->handle($request);
};

// --- PUBLIC ROUTES ---

$app->get('/', function (Request $request, Response $response) {
    $response->getBody()->write(json_encode(["status" => "API is live"]));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->post('/auth/login', function (Request $request, Response $response) {
    $data = $request->getParsedBody();
    $db = getDB();
    $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$data['email'] ?? '']);
    $user = $stmt->fetch();

    if ($user && password_verify($data['password'] ?? '', $user['password_hash'])) {
        $secret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET');
        $token = JWT::encode(['sub' => $user['id'], 'role' => $user['role'], 'email' => $user['email'], 'iat' => time(), 'exp' => time() + 36000], $secret, 'HS256');
        $response->getBody()->write(json_encode(['access_token' => $token, 'user' => $user]));
        return $response->withHeader('Content-Type', 'application/json');
    }
    $response->getBody()->write(json_encode(['error' => 'Invalid credentials']));
    return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
});

$app->get('/api/books', function (Request $request, Response $response) {
    $params = $request->getQueryParams();
    $db = getDB();
    $sql = "SELECT * FROM books";
    $args = [];
    if (!empty($params['q'])) {
        $sql .= " WHERE title LIKE ? OR author LIKE ?";
        $args = ["%" . $params['q'] . "%", "%" . $params['q'] . "%"];
    }
    $stmt = $db->prepare($sql);
    $stmt->execute($args);
    $response->getBody()->write(json_encode(['data' => $stmt->fetchAll()]));
    return $response->withHeader('Content-Type', 'application/json');
});

// --- PROTECTED ROUTES ---

$app->group('', function (\Slim\Routing\RouteCollectorProxy $group) {
    $group->get('/auth/me', function (Request $request, Response $response) {
        $user = $request->getAttribute('user');
        $db = getDB();
        $stmt = $db->prepare("SELECT id, name, email, role FROM users WHERE id = ?");
        $stmt->execute([$user['sub']]);
        $response->getBody()->write(json_encode($stmt->fetch()));
        return $response->withHeader('Content-Type', 'application/json');
    });

    $group->post('/api/books', function (Request $request, Response $response) {
        $data = $request->getParsedBody();
        $user = $request->getAttribute('user');
        $db = getDB();
        $stmt = $db->prepare("INSERT INTO books (title, author, year, created_by) VALUES (?, ?, ?, ?)");
        $stmt->execute([$data['title'], $data['author'], $data['year'], $user['sub']]);
        $response->getBody()->write(json_encode(['message' => 'Created']));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    });

    $group->delete('/api/books/{id}', function (Request $request, Response $response, array $args) {
        $user = $request->getAttribute('user');
        if ($user['role'] !== 'admin') {
            $response->getBody()->write(json_encode(['error' => 'Admins only']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }
        $db = getDB();
        $stmt = $db->prepare("DELETE FROM books WHERE id = ?");
        $stmt->execute([$args['id']]);
        $response->getBody()->write(json_encode(['message' => 'Deleted']));
        return $response->withHeader('Content-Type', 'application/json');
    });
})->add($authMiddleware);

$app->run();