/**
 * @fileoverview - Generates the yararules.html page dynamically.
 * @Author - Graham Thomas
 * @Dependencies - Chart.min.js, datatables.min.js, feather.min.js, bootstrap.min.js, sitefunctions.js
 */


/**
 * YaraPage constructor
 * @param {string} sel
 * @param {string} table
 * @param {string} chart
 * @constructor
 */
function YaraPage(sel, table, chart){
    // keep reference to IndexGen object
    var that = this;

    // required for generating chart with Chart.js
    var ctx = document.getElementById(chart);

    // opens request to API and waits for successful response
    var request = new XMLHttpRequest({mozSystem: true});
    var url = 'http://10.55.200.100:3000/api/staticoutput';
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            // parses json and performs actions on parsed response
            var response = JSON.parse(this.responseText);
            getElements(response);
        }
    };
    request.open("GET", url, true);
    request.send();

    // array of names of Yara rule names or 'No matches'
    var yaraRules = [];

    // array of randomly generated colors
    var colors = [];
    getElements = function (response) {
        for (var i = 0; i < response.length; i++) {
            // check if the Yara rule is a string and push that string into the array
            if (typeof(response[i].output[2].Yara_output) === "string") {
                yaraRules.push(response[i].output[2].Yara_output);
            }
            // if it is not a string, it matched a Yara Rule, so push that rule into the array
            else {
                var output = response[i].output[2];
                for(var j = 0; j < output.Yara_output.length; j++) {
                    yaraRules.push(output.Yara_output[j].Rule);
                }
            }
        }
        // remove duplicate yara rules
        var noDupYara = yaraRules.filter(function (item, i, ar) {
            return ar.indexOf(item) === i;
        });

        // array of objects containing Yara rules and the count of those rules
        var yaraObjects = [];
        for (var i = 0; i < noDupYara.length; i++) {
            var yaracount = count(noDupYara[i], yaraRules);
            var yaraObject = {rule: noDupYara[i], count: yaracount};
            yaraObjects.push(yaraObject)
        }
        // generates a random color for the total number of yara objects
        for (var i = 0; i < yaraObjects.length; i++) {
            colors.push(getRandomColor());
        }

        // sorts the array by the count
        yaraObjects.sort(function (a, b) {
            return b.count - a.count
        });

        // generates the bar graph
        generateChart(ctx, yaraObjects, colors);

        // gets the html for the table and sets it up
        var html = that.setUpTable(yaraObjects);
        $(sel).html(html);

        // reference to the DataTable for information access
        $(table).DataTable({
            "pageLength": 50
        });

        // generates the sidebar with Known Files and Flagged Files
        new SidebarNoTable();
    }
}

/**
 * Set up the YARA rules table
 * @param information
 * @returns {string}
 */
YaraPage.prototype.setUpTable = function(information){
    // basic html to set up first part of table
    var html = '<table class="table table-hover table-bordered"'
        + ' id="yaraTable" cellspacing="0"><thead class="thead-dark"><tr><th>Yara Rule'
        + '</th><th>Count</th></tr></thead>';

    // begin loophtml
    var loopHtml = "<tbody>";

    // loop to get all Yara information
    for (var i = 0; i < information.length; i++){
        loopHtml += "<tr><td>" + information[i].rule + "</td><td>" + information[i].count + "</td></tr>";
    }

    // close table
    loopHtml += "</tbody></table>";
    html += loopHtml;
    return html;
};
