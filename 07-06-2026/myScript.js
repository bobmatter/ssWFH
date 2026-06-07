window.getUserData = async function (info) {

        async function onCompletion(status, message, servererror) {
 
            var messageDetails = {
                message: message
            };

            await removeEl("adapdIDEl");
            if (status === "success") {
                if (info.onSuccess) {
                    info.onSuccess(messageDetails);
                    return;
                }
            } else if (status === "failed") {
                if (info.onFailure) {
                    messageDetails.servererror = servererror;
                    info.onFailure(messageDetails);
                    return;
                }
            }
            console.log(message);
        }
 
        if (validateAndShow()) {
            return;
        }
        toggleLoadMask();
        try {
            var deviceDetails = await getDeviceDetails();
            var details = {'agent': deviceDetails.user_agent, 'platform': deviceDetails.platform };
            var deviceType;
            var userAgent = navigator.userAgent;
            var platform = navigator.platform;
            var isTouchDevice = navigator.maxTouchPoints > 0;
            if ((isTouchDevice && (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent)) && (platform.includes('Linux'))) ||
                (isTouchDevice && (platform.includes('Linux'))) || (isTouchDevice && (/iPhone|iPad|iPod/i.test(userAgent)) && ((platform.includes('iPhone')) || (platform.includes('iPad')) || (platform.includes('iPod'))))
            ) {
                deviceType = 'mobile';
            } else {
                deviceType = 'web';
            }
 
            try {
                var os_name = detailsObj.osName;
                var behaviourDataTemplate = {
                    "device_info": [
                        {
                            "device_id": "",
                            "device_type": deviceType,
                            "device_component": os_name,
                            "device_component_version": "",
                            "device_sub_component": "",
                            "device_sub_component_version": "",
                            "device_version": ""
                        }
                    ]
                };
 
                // ============ FIXED: replaced spread (...) with Object.assign ============
                var maindata = Object.assign(
                    {},
                    deviceDetails,
                    behaviourDataTemplate,
                    {
                        model_type: "sentence",
                        source: "login",
                        behaviour_data_type: "keypress",
                        behaviour_data: await getLoginKeyStrokeData(),
                        mouse_data: mouseData,
                        checkbox: false,
                    }
                );
                console.log(maindata)
                console.log(behaviourData);
                showError('SUBMIT', behaviourData)
                var finalData = {
                    behaviourData: behaviourData,
                    details: details
                };
                showError('SUBMIT', finalData);
                document.getElementById("hiddenField").value = JSON.stringify(finalData);
            }
            catch (error) {
                console.log(error);
                await onCompletion("failed", error.message, true);
            }
        }
        catch (error) {
            await onCompletion("failed", error.message, true);
        }
        finally {
            key_dt = '';
            loginKeyDownEventsInfo = [];
            loginKeyUpEventsInfo = [];
            loginKeyUpKeyCount = {};
            loginKeyDownKeyCount = {};
            mouseData = [];
            keyDataInfo = [];
        } 
        toggleLoadMask();
    };
 
    function loadAndInsertAdapdIDHTML() {
 
        var fallbackWords = [
            "apple", "bridge", "castle", "dragon", "eagle",
            "forest", "garden", "harbor", "island", "jungle",
            "kitten", "lantern", "marble", "nectar", "ocean",
            "pillar", "quartz", "river", "sunset", "timber",
            "umbrella", "valley", "window", "yellow", "zebra",
            "anchor", "breeze", "cluster", "dewdrop", "ember",
            "flicker", "glacier", "harvest", "ivory", "jasmine",
            "keeper", "lemon", "meadow", "noble", "orbit",
            "pebble", "quiet", "raindrop", "silver", "tunnel",
            "crimson", "delta", "echo", "falcon", "granite",
            "hollow", "inlet", "jewel", "kelp", "lunar",
            "mosaic", "nimbus", "opal", "prism", "riddle",
            "spiral", "thorn", "vortex", "willow", "amber",
            "blaze", "coral", "drift", "frost", "gloom",
            "haze", "iris", "jade", "knoll", "lava",
            "mist", "nova", "onyx", "peak", "quest",
            "reef", "stone", "tide", "veil", "wave",
            "bloom", "cobalt", "dune", "flint", "grove",
            "helm", "icon", "kite", "lodge", "manor",
            "olive", "plaza", "quill", "rune", "slate",
            "trove", "vigor", "whirl", "yield", "acorn",
            "birch", "cedar", "daisy", "elder", "fern",
            "hazel", "indigo", "juniper", "lilac", "maple",
            "nettle", "pine", "robin", "sage", "thyme",
            "wren", "yarrow", "cliff", "storm", "flame",
            "spark", "cloud", "creek", "field", "plain",
            "tower", "brook", "bough", "twig", "briar",
            "chalk", "floss", "gleam", "graft", "hedge"
        ];
 
        function getFallbackWords() {
            var words = [];
            while (words.length < 300) {
                words.push.apply(words, fallbackWords);
            }
            return words.slice(0, 300);
        }
 
        var adapdData = [fetch(randomWordsURL)];
        // ============ FIXED: removed all ?. in promise chain ============
        Promise.all(adapdData).then(function (responses) {
            var words = responses[0];
            console.log("[AdapdID] API Status:", words.status, "| OK:", words.ok);
            return Promise.all([words.json()]);
 
        }).then(async function (results) {
            var words = results[0];
            console.log("[AdapdID] API Response:", words);
            console.log("[AdapdID] Words count:", words.words ? words.words.length : "words.words is MISSING in response");
 
            if (!words.words || !words.words.length) {
                throw new Error("Empty or invalid words from API");
            }
 
            verificationTexts = words.words;
            await addListenersToAdapdIDHTML();
            var newText = instanceObj.verificationTextInfo.updatetAndGetVerificationText();
            await updateVerificationText(newText);
            console.log("[AdapdID] Phrase on screen:", instanceObj.verificationTextInfo.getCurrentVerificationText());
 
        }).catch(async function (e) {
            console.warn("[AdapdID] Failed – Reason:", e.message);
 
            verificationTexts = getFallbackWords();
            await addListenersToAdapdIDHTML();
            var newText = instanceObj.verificationTextInfo.updatetAndGetVerificationText();
            await updateVerificationText(newText);
        });
    }
 
    function getElById(elId) {
        return document.getElementById(elId);
    }
 
    // ============ FIXED: removed ?. ============
    async function removeEl(elID) {
        var elementToRemove = getElById(elID);
        if (elementToRemove) {
            elementToRemove.remove();
        }
    }
 
    window.adapdIDInstance = null;
 
    loadAndInsertAdapdIDHTML();
 
    return adapdIDInstance;
};
