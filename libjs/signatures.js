/**
 * @fileoverview - Generates the signature information for the table
 * @Author - Graham Thomas
 * @Dependencies - sidebarnotable.js, Chart.min.js, datatables.min.js
 */

/**
 *
 * @param {string} sel
 * @param {string} table
 * @param {string} chart
 * @constructor
 */
function SignaturePage(sel, table, chart){
    // keep reference to IndexGen object
    var that = this;

    // required for generating chart with Chart.js
    var ctx = document.getElementById(chart);

    // opens request to API and waits for successful response
    var request = new XMLHttpRequest({mozSystem: true});
    var url = 'http://10.55.200.100:3000/api/signature';
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            // parses json and performs actions on parsed response
            var response = JSON.parse(this.responseText);
            getElements(response);
        }
    };
    request.open("GET", url, true);
    request.send();

    // array of signature names
    var signatures = [];

    // array of colors for the chart
    var colors = [];

    getElements = function (response) {
        // push all the signatures into an array
        for(var i = 0; i < response.length; i++){
            for(var j = 0; j < response[i].signatures.length; j++){
                signatures.push(response[i].signatures[j].name);
            }
        }
        // remove duplicates in the array
        var noDupSig = signatures.filter(function (item, i, ar) {
            return ar.indexOf(item) === i;
        });

        // array of signature objects
        var sigObjs = [];

        // push the signature objects into the array
        for (var i = 0; i < noDupSig.length; i++) {
            var sigCount = count(noDupSig[i], signatures);
            var sigObj = {rule: noDupSig[i], count: sigCount};
            sigObjs.push(sigObj)
        }

        // get an array of colors equal to the length of the signature objects array
        for (var i = 0; i < sigObjs.length; i++) {
            colors.push(getRandomColor());
        }

        // sort the array in descending order
        sigObjs.sort(function (a, b) {
            return b.count - a.count
        });

        // call generate chart sitewide function
        generateChart(ctx, sigObjs, colors);

        // set up the table of the signature objects
        var html = that.setUpTable(sigObjs);
        $(sel).html(html);

        $(table).DataTable({
            "pageLength": 10
        });
        // generates the sidebar with Known Files and Flagged Files
        new SidebarNoTable();
    }
}

/**
 * Generate the signature table
 * @param {array} information
 * @returns {string}
 */
SignaturePage.prototype.setUpTable = function(information){
    // set up the headers for the table
    var html = '<table class="table table-hover table-bordered"'
        + ' id="signatureTable" cellspacing="0"><thead class="thead-dark"><tr><th>Signature Name'
        + '</th><th>Count</th></tr></thead>';

    // get the loop html started
    var loopHtml = "<tbody>";

    // add the rule and count to the table
    for (var i = 0; i < information.length; i++){
        loopHtml += "<tr><td>" + information[i].rule + "</td><td>" + information[i].count + "</td></tr>";
    }

    // close the table and return
    loopHtml += "</tbody></table>";
    html += loopHtml;
    return html;
};