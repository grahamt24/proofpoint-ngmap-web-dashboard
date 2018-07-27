/**
 * @fileoverview - Functions that will be used throughout the site
 * @Author - Graham Thomas
 * @Dependencies - Chart.min.js
 */

/**
 * Generates a random color
 * @returns {string}
 */
function getRandomColor() {
    // characters that can be in a color's hex code
    var letters = '0123456789ABCDEF';

    // starts the hex code
    var color = '#';

    // selects a random character six times to get a hex code
    for (var i = 0; i < 6; i++) {
        color += letters[Math.floor(Math.random() * 16)];
    }
    return color;
}

/**
 * Gets the parameter in the url
 * @param parameterName
 * @returns {*}
 */
function findGetParameter(parameterName) {
    // initializes the results to be null
    var result = null;

    // results split by & and =
    var splitResults = [];
    location.search.substr(1).split("&")
        .forEach(function (item) {
            splitResults = item.split("=");
            if (splitResults[0] === parameterName) {
                result = decodeURIComponent(splitResults[1]);
            }
        });
    return result;
}

/**
 * Rounds to the nearest precision value
 * @param {number} value
 * @param {number} precision
 * @returns {number}
 */
function round(value, precision) {
    var multiplier = Math.pow(10, precision || 0);
    return Math.round(value * multiplier) / multiplier;
}


/**
 * Count the total number of the given item in the list
 * @param {string} item
 * @param {array} info
 * @returns {number}
 */
function count(item, info) {
    // initialize count
    var count = 0;

    // count the number of times the rule appears
    for (var i = 0; i < info.length; i++) {
        if (info[i] === item) {
            count++;
        }
    }
    return count;
}

/**
 * Generates a chart to display the count of the Yara Rules analyzed.
 * @param {string} ctx
 * @param {array} objects
 * @param {array} colors
 */
function generateChart(ctx, objects, colors){
    // array of Yara rules
    var info = [];

    // array of Yara rule counts
    var counts = [];


    var loopNum = 0;
    if(objects.length >= 25){
        loopNum = 25;
    }
    else{
        loopNum = objects.length;
    }

    // separate the Yara object (rule, count) into their own arrays
    for (var i = 0; i < loopNum; i++) {
        if(objects[i].count > 1) {
            info.push(objects[i].rule);
            counts.push(objects[i].count);
        }
    }

    // create a new chart with the data set
    new Chart(ctx, {
        type: 'horizontalBar',
        data: {
            labels: info,
            datasets: [{
                data: counts,
                backgroundColor: colors,
                borderWidth: 0
            }]
        },
        options: {
            legend:{
                display: false
            },
            scales: {
                xAxes: [{
                    ticks: {
                        beginAtZero: true,
                        suggestedMin: 0
                    }
                }],
                yAxes: [{
                    ticks: {
                        beginAtZero: true
                    }
                }]
            }
        }
    });
}

/**
 * Convert ms to a mm:ss.sss format
 * @param {number} s
 * @returns {string}
 */
function msToTime(s) {

    // Pad to 2 or 3 digits, default is 2
    function pad(n, z) {
        z = z || 2;
        return ('00' + n).slice(-z);
    }

    var ms = s % 1000;
    s = (s - ms) / 1000;
    var secs = s % 60;
    s = (s - secs) / 60;
    var mins = s % 60;

    return pad(mins) + ':' + pad(secs) + '.' + pad(ms, 3);
}

/**
 * Convert hrs, min, sec to milliseconds
 * @param {number} hrs
 * @param {number} min
 * @param {number} sec
 * @returns {number}
 */
function milliseconds(hrs, min, sec){
    return ((hrs*60*60+min*60+sec)*1000);
}