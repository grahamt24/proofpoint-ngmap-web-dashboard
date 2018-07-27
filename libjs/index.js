/**
 * @fileoverview - Generates the index.html page and populates the chart and table with data.
 * @Author - Graham Thomas
 * @Dependencies - jquery-3.2.1.min.js, feather.min.js, sidebarnotable.js, percircle.js, bootstrap.min.js,
 *                 sitefunctions.js
 */

/**
 * Constructor for the IndexGen instance
 * @param {string} table
 * @constructor
 */
function IndexGen(table) {
    // keep reference to IndexGen object
    var that = this;

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

    // array of arrays containing every item from the API response
    var information = [];

    // array of names of Yara rule names or 'No matches'
    var yaraRules = [];

    // array of analysis times
    var times = [];

    // array of cuckoo IDs
    var cuckooIDs = [];

    getElements = function (response) {
        if(response.length === 0){
            $("#flaggedfilecircle").percircle({
                percent: 0,
                progressBarColor: "#DC3545"
            });
            $("#knownfilecircle").percircle({
                percent: 0,
                progressBarColor: "#28A745"
            });
            // set file count and format it to have commas
            $("#filecount").html(0);

            // set cluster number and format it to have commas
            $("#clusternum").html(0);
        }
        else {
            for (var i = 0; i < response.length; i++) {
                // check if the Yara rule is a string and push that string into the array
                if (typeof(response[i].output[2].Yara_output) === "string") {
                    yaraRules.push(response[i].output[2].Yara_output);
                }
                // if it is not a string, it matched a Yara Rule, so push that rule into the array
                else {
                    var output = response[i].output[2];
                    for (var j = 0; j < output.Yara_output.length; j++) {
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
                var yaraCount = count(noDupYara[i], yaraRules);
                var yaraObject = {rule: noDupYara[i], count: yaraCount};
                yaraObjects.push(yaraObject)
            }

            // sorts the array by the count
            yaraObjects.sort(function (a, b) {
                return b.count - a.count
            });

            // pushes all the responses into an array, then pushes that array into the overall array
            for (var i = 0; i < response.length; i++) {
                // all the information received from API response
                var info = [];
                info.push(i);
                info.push(response[i].output[0].name);
                info.push(response[i].output[1].extension);
                info.push(response[i].output[2].Yara_output);
                info.push(response[i].output[3].PEHash);
                info.push(response[i].output[4].sha256);
                info.push(response[i].output[5].sha1);
                info.push(response[i].output[6].md5);
                info.push(response[i]._id);
                times.push(response[i].output[8].Static_Runtime);
                if(response[i].output[9].Cuckoo_ID !== "-1"){
                    cuckooIDs.push(response[i].output[9].Cuckoo_ID);
                }
                information.push(info);
            }

            // generates the sidebar with Known Files and Flagged Files
            new SidebarNoTable();

            // total time for getting average
            var totalTime = 0;
            for (var i = 0; i < times.length; i++) {
                // split the times by the : (string should be formatted 00:00:00.000)
                var split = times[i].split(":");

                // get the hours from the split
                var hours = split[0];

                // get the minutes from the split
                var minutes = split[1];

                // split the seconds by the . for s and ms
                var secSplit = split[2].split(".");

                // seconds of the time
                var seconds = secSplit[0];

                // add the number of milliseconds for the item to the total number of milliseconds
                totalTime += milliseconds(parseInt(hours), parseInt(minutes), parseInt(seconds)) + parseInt(secSplit[1]);
            }

            // average time of static analysis
            var avgTime = totalTime / times.length;

            // set the average time div to the formatted string
            $("#averagetime").html(msToTime(avgTime));

            // count of the number of flagged files
            var flaggedCount = 0;

            // count of the number of known files
            var knownCount = 0;

            // counts the number of flagged and known files in the system
            for (var i = 0; i < response.length; i++) {
                if (response[i].output[2].Yara_output === "No Matches") {
                    flaggedCount += 1;
                }
                else {
                    knownCount += 1;
                }
            }

            // percentage of known files in the system
            var knownPercentage = (knownCount / response.length) * 100;

            // percentage of flagged files in the system
            var flaggedPercentage = (flaggedCount / response.length) * 100;

            // rounded percentage of flagged files
            var roundedFlagged = round(flaggedPercentage, 1);

            // rounded percentage of flagged files
            var roundedKnown = round(knownPercentage, 1);

            // generates the html for the cards (the percentage circle and the total number of files analyzed)
            $("#flaggedfilecircle").percircle({
                percent: roundedFlagged,
                progressBarColor: "#DC3545"
            });
            $("#knownfilecircle").percircle({
                percent: roundedKnown,
                progressBarColor: "#28A745"
            });
            // set file count and format it to have commas
            $("#filecount").html(information.length.toLocaleString());

            // set cluster number and format it to have commas
            $("#clusternum").html(noDupYara.length.toLocaleString());

            // get the rounded value of percentage of files undergoing dynamic analysis
            var dynamicRounded = round((cuckooIDs.length / response.length)*100, 1);
            $("#dynamiccircle").percircle({
                percent: dynamicRounded,
                progressBarColor: "#007bff"
            });

            // set the div to a localized string (x,xxx style) for total number of files undergoing dynamic analysis
            $("#dynamicnum").html(cuckooIDs.length.toLocaleString());

            // generate the html for the yara card/table
            var yaraHTML = '<table class="table table-hover table-bordered"'
                + ' id="malwareTable" cellspacing="0"><thead class="thead-dark"><tr><th>YARA Rule'
                + '</th><th>Count</th></tr></thead>';
            yaraHTML += '<tbody>';

            for (var i = 0; i < 5; i++) {
                yaraHTML += '<tr><td>' + yaraObjects[i].rule + '</td><td>' + yaraObjects[i].count + '</td></tr>';
            }
            yaraHTML += '</tbody></table>';
            $("#top5yara").html(yaraHTML);
        }
    };
}