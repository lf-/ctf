<?php
include(__DIR__ . '/vendor/autoload.php');

use PhpParser\BuilderHelpers;
use PhpParser\ConstExprEvaluationException;
use PhpParser\ConstExprEvaluator;
use PhpParser\Node;
use PhpParser\NodeDumper;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
$ast = $parser->parse(file_get_contents($argv[1]));
$dumper = new NodeDumper;

$evaluator = new ConstExprEvaluator();

class Visitor extends NodeVisitorAbstract {
    public function leaveNode(Node $node): Node {
        global $evaluator;
        global $dumper;

        if ($node instanceof Node\Expr) {
            try {
                $evald = $evaluator->evaluateSilently($node);
                return BuilderHelpers::normalizeValue($evald);
            } catch (ConstExprEvaluationException $e) {
                // echo "err: $e";
            }
        }
        if ($node instanceof Node\Expr\FuncCall) {
            try {
                $name = ($node->name instanceof Node\Expr) ? $evaluator->evaluateSilently($node->name) : $node->name;
                switch ($name) {
                    case 'abs':
                        $arg = $evaluator->evaluateSilently($node->getArgs()[0]->value);
                        return BuilderHelpers::normalizeValue(abs($arg));
                    case 'strstr':
                        $a1 = $evaluator->evaluateSilently($node->getArgs()[0]->value);
                        $a2 = $evaluator->evaluateSilently($node->getArgs()[1]->value);
                        return BuilderHelpers::normalizeValue(strstr($a1, $a2));
                }

                // Fix ('printf')('blah') -> printf('blah')
                $node->name = new Node\Name($name);
                // echo $dumper->dump($node) . '\n';
                return $node;
            } catch (ConstExprEvaluationException $e) {}
        }

        // echo $dumper->dump($node) . '\n';

        return $node;
    }
}

$traverser = new NodeTraverser;
$traverser->addVisitor(new Visitor());

$newAst = $traverser->traverse($ast);
$pp = new PhpParser\PrettyPrinter\Standard();
$s = $pp->prettyPrintFile($newAst);
file_put_contents($argv[2], $s);

// echo $dumper->dump($ast);
