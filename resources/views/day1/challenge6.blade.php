<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Challenge 6</title>
    <style>
        body {
            background-color: #fff;
        }

        .fw {
            position: absolute;
            top: 0px;
            right: 0px;
            bottom: 0px;
            left: 0px;
            z-index: 1;
            overflow: hidden;
        }

        .ct {
            z-index: 10;
            position: relative;
        }
    </style>
</head>

<body>

    <p><a href="/day1/challenge6">Reset form</a></p>

    <h1>Script Injection</h1>

    <h2>Objective</h2>

    <ul>
        <li>Load the script `http://localhost:3000/scripts/xss.js` onto the page.
        </li>
    </ul>

    <details>
        <summary>Possible solution</summary>
        <pre>
");
var script = document.createElement('script');
script.src = 'http://localhost:3000/scripts/xss.js';
document.head.appendChild(script);
//
</pre>
    </details>
    <form method="POST">
        @csrf
        <p>Add some markdown</p>
        <div>
            <textarea type="text" name="description" id="description" style="width: 95%" placeholder="Some markdown"
                value="{!! strip_tags(request()->get('description')) !!}" />
            </textarea>
        </div>
        <p><button type="submit">Search!</button></p>
    </form>
    @if (request()->isMethod('POST'))
        <h3>Your formatted description:</h3>
        <p>
            <script>
                document.write("{!! strip_tags(request()->get('description')) !!}");
            </script>
        </p>
        </p>
    @endif

</body>

</html>
