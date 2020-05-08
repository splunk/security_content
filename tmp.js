webpackJsonp([40], {
    0: function(e, t, a) {
        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        a.p = function() {
            function e() {
                for (var e, a, n = "", l = 0, r = arguments.length; l < r; l++) e = arguments[l].toString(), a = e.length, a > 1 && "/" == e.charAt(a - 1) && (e = e.substring(0, a - 1)), n += "/" != e.charAt(0) ? "/" + e : e;
                if ("/" != n) {
                    var o = n.split("/"),
                        i = o[1];
                    if ("static" == i || "modules" == i) {
                        var s = n.substring(i.length + 2, n.length);
                        n = "/" + i, window.$C.BUILD_NUMBER && (n += "/@" + window.$C.BUILD_NUMBER), window.$C.BUILD_PUSH_NUMBER && (n += "." + window.$C.BUILD_PUSH_NUMBER), "app" == o[2] && (n += ":" + t("APP_BUILD", 0)), n += "/" + s
                    }
                }
                var u = t("MRSPARKLE_ROOT_PATH", "/"),
                    d = t("DJANGO_ROOT_PATH", ""),
                    f = t("LOCALE", "en-US"),
                    c = "";
                return c = d && n.substring(0, d.length) === d ? n.replace(d, d + "/" + f.toLowerCase()) : "/" + f + n, "" == u || "/" == u ? c : u + c
            }

            function t(e, t) {
                if (window.$C && window.$C.hasOwnProperty(e)) return window.$C[e];
                if (void 0 !== t) return t;
                throw new Error("getConfigValue - " + e + " not set, no default provided")
            }
            return e("/static/app/SplunkEnterpriseSecuritySuite/build/pages") + "/"
        }();
        var l = a("shim/jquery"),
            r = n(l),
            o = a(1),
            i = a(1453),
            s = n(i),
            u = a(1456),
            d = n(u),
            f = a(1607),
            c = a(2929),
            p = n(c);
        a(57), (0, r.default)(".preload").remove(), (0, d.default)(s.default.createElement(p.default, null), {
            pageTitle: (0, o._)("Use Case Library")
        }), (0, f.checkForTour)()
    },
    2199: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }

        function l(e) {
            var t = b.default.duration(e, "seconds");
            return Math.floor(t.asHours()) + b.default.utc(t.asMilliseconds()).format(":mm:ss")
        }

        function r(e, t) {
            var a = void 0,
                n = String(t);
            if ("avg_event_count" === e) a = (0, S._)("Avg. Event Count"), n = (0, _.abbreviateNumber)(t);
            else if ("avg_result_count" === e) a = (0, S._)("Avg. Result Count"), n = (0, _.abbreviateNumber)(t);
            else if ("avg_run_time" === e) a = (0, S._)("Avg. Run Time"), n = l(t);
            else if ("invocations" === e) a = (0, S._)("Invocations"), n = (0, _.abbreviateNumber)(t);
            else if ("skipped" === e) a = (0, S._)("Skipped"), n = (0, _.abbreviateNumber)(t);
            else if ("success" === e) a = (0, S._)("Success"), n = (0, _.abbreviateNumber)(t);
            else if ("update_time" === e) {
                a = (0, S._)("Update Time");
                var r = b.default.unix(t);
                n = r.splunkFormat("lls")
            }
            return {
                label: a,
                value: n
            }
        }

        function o(e, t) {
            var a = void 0,
                n = String(t);
            if ("access_count" === e) a = (0, S._)("Access Count"), n = (0, _.abbreviateNumber)(t);
            else if ("access_time" === e) {
                a = (0, S._)("Last Access");
                var l = b.default.unix(t);
                n = l.splunkFormat("lls")
            } else if ("buckets" === e) a = (0, S._)("Buckets"), n = (0, _.abbreviateNumber)(t);
            else if ("buckets_size" === e) a = (0, S._)("Buckets Size"), n = (0, _.bytesToFileSize)(t);
            else if ("complete" === e) a = (0, S._)("Complete"), n = (0, S._)("%d% Completed").replace("%d", (100 * t).toFixed(2));
            else if ("earliest_time" === e) {
                a = (0, S._)("Earliest Time");
                var o = b.default.unix(t);
                n = o.splunkFormat("lls")
            } else if ("is_inprogress" === e) a = (0, S._)("In Progress");
            else if ("last_error" === e) a = (0, S._)("Last Error");
            else if ("latest_time" === e) {
                a = (0, S._)("Latest Time");
                var i = b.default.unix(t);
                n = i.splunkFormat("lls")
            } else if ("mod_time" === e) {
                a = (0, S._)("Last Modified");
                var s = b.default.unix(t);
                n = s.splunkFormat("lls")
            } else if ("size" === e) a = (0, S._)("Size on Disk"), n = (0, _.bytesToFileSize)(t);
            else if ("time_range" === e) a = (0, S._)("Summary Range"), n = b.default.duration(t, "seconds").humanize();
            else {
                if ("update_time" !== e) return r(e, t);
                a = (0, S._)("Update Time");
                var u = b.default.unix(t);
                n = u.splunkFormat("lls")
            }
            return {
                label: a,
                value: n
            }
        }

        function i(e, t, a, n) {
            var l = arguments.length > 4 && void 0 !== arguments[4] ? arguments[4] : {
                    output_mode: "json",
                    count: -1
                },
                r = void 0 !== t ? "/" + encodeURIComponent(t) : "";
            return (0, k.fetchRESTURL)("contentinfo/" + encodeURIComponent(e) + r, {
                owner: a,
                app: n
            }, l)
        }

        function s(e) {
            return new Map(Object.keys(e).sort().map(function(t) {
                return [t, e[t].map(function(e) {
                    return {
                        label: e,
                        id: e
                    }
                })]
            }))
        }

        function u(e) {
            return Object.keys(e).sort().map(function(t) {
                var a = e[t],
                    n = a.readiness,
                    l = a.quality;
                return {
                    label: t,
                    id: t,
                    readiness: n,
                    quality: l
                }
            })
        }

        function d(e) {
            return new Map(Object.keys(e).sort().map(function(t) {
                return [t, u(e[t])]
            }))
        }

        function f(e) {
            return Object.keys(e).sort().map(function(t) {
                return {
                    value: e[t],
                    id: t
                }
            })
        }

        function c(e) {
            return e.map(function(e) {
                return {
                    label: e,
                    id: e
                }
            })
        }

        function p(e) {
            var t = {};
            if (e && e.entry && e.entry.length > 0 && e.entry[0].content) {
                var a = e.entry[0].content;
                a.stats && (t.stats = f(a.stats)), a.associations && (t.associations = s(a.associations)), a.datasets && (t.datasets = d(a.datasets)), a.tags && (t.tags = c(a.tags))
            }
            return t
        }

        function m(e) {
            return (0, v.default)({}, e.stats ? {
                stats: e.stats
            } : {}, e.associations && e.associations.has("datamodel") ? {
                associationsDataModels: e.associations.get("datamodel")
            } : {}, e.associations && e.associations.has("panel") ? {
                associationsPanels: e.associations.get("panel")
            } : {}, e.associations && e.associations.has("savedsearch") ? {
                associationsSavedsearches: e.associations.get("savedsearch")
            } : {}, e.associations && e.associations.has("view") ? {
                associationsViews: e.associations.get("view")
            } : {}, e.datasets && e.datasets.has("datamodel") ? {
                datasetsDataModels: e.datasets.get("datamodel")
            } : {}, e.datasets && e.datasets.has("index") ? {
                datasetsIndexes: e.datasets.get("index")
            } : {}, e.datasets && e.datasets.has("lookup") ? {
                datasetsLookups: e.datasets.get("lookup")
            } : {}, e.datasets && e.datasets.has("savedsearch") ? {
                datasetsSavedSearches: e.datasets.get("savedsearch")
            } : {}, e.datasets && e.datasets.has("sourcetype") ? {
                datasetsSourcetypes: e.datasets.get("sourcetype")
            } : {}, e.tags ? {
                tags: e.tags
            } : {})
        }

        function h(e, t, a, n) {
            return i(e, t, a, n).then(function(e) {
                return m(p(e))
            })
        }

        function g(e, t) {
            if (0 === t) {
                if ("datamodel" === e) return (0, S._)("The datamodel's datasets are not ingesting enough data for this content to report accurately.");
                if ("index" === e) return (0, S._)("The index has no events from the past 24 hours.");
                if ("lookup" === e) return (0, S._)("Lookup file is not populated.");
                if ("savedsearch" === e) return (0, S._)("The savedsearch's datasets are not ingesting enough data for this content to report accurately.");
                if ("sourcetype" === e) return (0, S._)("The sourcetype has no events from the past 24 hours.")
            } else if (1 === t) {
                if ("datamodel" === e) return (0, S._)("The datamodel's datasets are ingesting enough data for this content to report accurately.");
                if ("index" === e) return (0, S._)("The index has events from the past 24 hours.");
                if ("lookup" === e) return (0, S._)("Lookup file is populated.");
                if ("savedsearch" === e) return (0, S._)("The savedsearch's datasets are ingesting enough data for this content to report accurately.");
                if ("sourcetype" === e) return (0, S._)("The sourcetype has events from the past 24 hours.")
            }
            return null
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var y = a(1353),
            v = n(y);
        t.getSearchLabelAndNormalizedValue = r, t.getDataModelLabelAndNormalizedValue = o, t.fetchContentInfo = i, t.parseAssociations = s, t.parseDataset = u, t.parseDatasets = d, t.parseStats = f, t.parseTags = c, t.handleContentInfoResponse = p, t.flattenContentInfo = m, t.fetchParseFlattenContentInfo = h, t.getReasonForReadiness = g;
        var k = a(886),
            S = a(1),
            _ = a(1699),
            C = a(1701),
            b = n(C);
        a(57)
    },
    2203: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1461),
            h = n(m),
            g = a(1621),
            y = n(g),
            v = a(1620),
            k = n(v),
            S = a(2204),
            _ = n(S),
            C = a(2205),
            b = n(C);
        a(57);
        var E = function(e) {
            function t() {
                return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
            }
            return (0, f.default)(t, e), (0, i.default)(t, [{
                key: "getTruncatedListItems",
                value: function(e, t) {
                    var a = Math.max(0, t);
                    return e.slice(0, a).map(function(e) {
                        return p.default.createElement(k.default, {
                            key: e.id,
                            "data-test-value": e.label
                        }, p.default.createElement(b.default, {
                            readiness: e.readiness,
                            reason: e.reason
                        }), "" === e.url || void 0 === e.url ? e.label : p.default.createElement(y.default, {
                            to: e.url,
                            openInNewContext: !0
                        }, e.label))
                    })
                }
            }, {
                key: "getListModal",
                value: function(e, t, a, n) {
                    var l = Math.max(0, t);
                    return e.length > l ? p.default.createElement(_.default, {
                        "data-test": "list-modal",
                        items: e,
                        anchorLabel: a,
                        titleText: n
                    }) : null
                }
            }, {
                key: "render",
                value: function() {
                    var e = this.props,
                        t = e.items,
                        a = e.maxItemsShown,
                        n = e.anchorButtonLabel,
                        l = e.modalTitle;
                    return p.default.createElement(p.default.Fragment, null, this.getTruncatedListItems(t, a), this.getListModal(t, a, n, l))
                }
            }]), t
        }(c.Component);
        E.propTypes = {
            items: h.default.arrayOf(h.default.shape({
                label: h.default.string.isRequired,
                url: h.default.string,
                id: h.default.string.isRequired,
                readiness: h.default.number,
                reason: h.default.string,
                quality: h.default.number
            })).isRequired,
            maxItemsShown: h.default.number,
            anchorButtonLabel: h.default.string.isRequired,
            modalTitle: h.default.string.isRequired
        }, E.defaultProps = {
            maxItemsShown: 5
        }, t.default = E, e.exports = t.default
    },
    2204: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1),
            h = a(1633),
            g = n(h),
            y = a(1628),
            v = n(y),
            k = a(1621),
            S = n(k),
            _ = a(1620),
            C = n(_),
            b = a(1461),
            E = n(b),
            R = a(2205),
            M = n(R);
        a(57);
        var q = function(e) {
            function t(e, a) {
                (0, r.default)(this, t);
                var n = (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, a));
                return n.state = {
                    open: !1
                }, n.handleRequestClose = n.handleRequestClose.bind(n), n.handleRequestOpen = n.handleRequestOpen.bind(n), n
            }
            return (0, f.default)(t, e), (0, i.default)(t, [{
                key: "handleRequestOpen",
                value: function() {
                    this.setState({
                        open: !0
                    })
                }
            }, {
                key: "handleRequestClose",
                value: function() {
                    this.setState({
                        open: !1
                    })
                }
            }, {
                key: "render",
                value: function() {
                    var e = this.props,
                        t = e.items,
                        a = e.anchorLabel,
                        n = e.width,
                        l = e.titleText,
                        r = this.state.open,
                        o = t.map(function(e) {
                            return p.default.createElement(C.default, {
                                key: e.id,
                                "data-test-value": e.label
                            }, p.default.createElement(M.default, {
                                readiness: e.readiness,
                                reason: e.reason
                            }), "" === e.url || void 0 === e.url ? e.label : p.default.createElement(S.default, {
                                to: e.url,
                                openInNewContext: !0
                            }, e.label))
                        });
                    return p.default.createElement(p.default.Fragment, null, p.default.createElement(v.default, {
                        "data-test": "list-modal-anchor-button",
                        onClick: this.handleRequestOpen,
                        label: a
                    }), p.default.createElement(g.default, {
                        onRequestClose: this.handleRequestClose,
                        open: r,
                        style: {
                            width: n
                        }
                    }, p.default.createElement(g.default.Header, {
                        "data-test": "list-modal-header",
                        title: l,
                        onRequestClose: this.handleRequestClose
                    }), p.default.createElement(g.default.Body, {
                        "data-test": "list-modal-body"
                    }, o), p.default.createElement(g.default.Footer, null, p.default.createElement(v.default, {
                        "data-test": "list-modal-close-button",
                        appearance: "primary",
                        onClick: this.handleRequestClose,
                        label: (0, m._)("Close")
                    }))))
                }
            }]), t
        }(c.Component);
        q.propTypes = {
            items: E.default.arrayOf(E.default.shape({
                label: E.default.string.isRequired,
                url: E.default.string,
                id: E.default.string.isRequired,
                readiness: E.default.number,
                reason: E.default.string,
                quality: E.default.number
            })).isRequired,
            anchorLabel: E.default.string.isRequired,
            titleText: E.default.string.isRequired,
            width: E.default.number
        }, q.defaultProps = {
            width: 600
        }, t.default = q, e.exports = t.default
    },
    2205: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1652),
            h = n(m),
            g = a(1809),
            y = n(g),
            v = a(1877),
            k = n(v),
            S = a(1461),
            _ = n(S);
        a(57);
        var C = {
                color: "#53A051",
                paddingRight: "4px"
            },
            b = {
                color: "#DC4E41",
                paddingRight: "4px"
            },
            E = function(e) {
                function t() {
                    return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
                }
                return (0, f.default)(t, e), (0, i.default)(t, [{
                    key: "render",
                    value: function() {
                        var e = this.props,
                            t = e.reason,
                            a = e.readiness;
                        if (null === a) return null;
                        var n = null !== t && "" !== t,
                            l = 1 === a ? p.default.createElement(k.default, {
                                screenReaderText: "",
                                style: C
                            }) : p.default.createElement(y.default, {
                                screenReaderText: "",
                                style: b
                            }),
                            r = n ? p.default.createElement(h.default, {
                                content: t
                            }, l) : l;
                        return r
                    }
                }]), t
            }(c.Component);
        E.propTypes = {
            readiness: _.default.number,
            reason: _.default.string
        }, E.defaultProps = {
            readiness: null,
            reason: null
        }, t.default = E, e.exports = t.default
    },
    2929: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(1733),
            r = n(l),
            o = a(3),
            i = n(o),
            s = a(1353),
            u = n(s),
            d = a(834),
            f = n(d),
            c = a(864),
            p = n(c),
            m = a(865),
            h = n(m),
            g = a(869),
            y = n(g),
            v = a(870),
            k = n(v),
            S = a(1453),
            _ = n(S),
            C = a(886),
            b = a(1358),
            E = a(1673),
            R = n(E),
            M = a(2930),
            q = n(M),
            O = a(2931),
            w = n(O),
            A = a(1619),
            T = n(A),
            D = a(1633),
            L = n(D),
            U = a(1620),
            I = n(U),
            B = a(1621),
            x = n(B),
            F = a(1628),
            P = n(F),
            j = a(1682),
            N = n(j),
            z = a(2126),
            H = a(1),
            K = a(889),
            W = a(1684),
            V = n(W),
            $ = a(1688),
            J = n($),
            G = a(1618),
            Q = n(G),
            X = a(1617),
            Y = n(X),
            Z = a(2935),
            ee = n(Z),
            te = a(2936),
            ae = n(te),
            ne = a(1352),
            le = a(1610),
            re = n(le),
            oe = a(888),
            ie = a(2199),
            se = a(1626);
        a(57);
        var ue = {},
            de = {
                output_mode: "json",
                count: -1,
                f: "datasets"
            },
            fe = {
                paddingLeft: 10,
                width: 190,
                float: "left"
            },
            ce = {
                marginLeft: 200
            },
            pe = {
                padding: "0 10px"
            },
            me = {
                paddingTop: 10,
                paddingBottom: 10,
                paddingRight: 10
            },
            he = {
                marginLeft: 1,
                paddingTop: 10
            },
            ge = function(e) {
                function t(e) {
                    (0, p.default)(this, t);
                    var a = (0, y.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e));
                    return a.state = {
                        useCases: [],
                        analyticStories: [],
                        selectedCategories: [],
                        searchValue: "",
                        searchTerm: "",
                        errorMsg: "",
                        isLoading: !0,
                        openDiscoverRecStoriesModal: !1,
                        dataModels: [],
                        dataSources: [],
                        apps: [],
                        modal: "",
                        optOut: !1,
                        annotations: [],
                        filterMetadata: [],
                        filterApp: "",
                        filterDataSource: "",
                        filterDataModel: "",
                        filterInUse: "",
                        filterBookmarked: "",
                        dataModelsSearchesMap: new Map,
                        dataSourcesSearchesMap: new Map
                    }, a.handleCategoryClick = a.handleCategoryClick.bind(a), a.handleSearchChange = a.handleSearchChange.bind(a), a.handleAnnotationClick = a.handleAnnotationClick.bind(a), a.handleBookmarkClick = a.handleBookmarkClick.bind(a), a.handleFiltersChange = a.handleFiltersChange.bind(a), a.handleMetadataFilterChange = a.handleMetadataFilterChange.bind(a), a.updateMetadataState = a.updateMetadataState.bind(a), a.setSearchTerm = (0, K.debounce)(a.setSearchTerm, 300), a.fetchSearchContentInfo = a.fetchSearchContentInfo.bind(a), a.currentUser = (0, C.getCurrentUser)(), a.fetchStoryContentInfo = a.fetchStoryContentInfo.bind(a), a.handleCloseESCUModal = a.handleCloseESCUModal.bind(a), a.handleOptOutClick = a.handleOptOutClick.bind(a), a
                }
                return (0, k.default)(t, e), (0, h.default)(t, [{
                    key: "componentWillMount",
                    value: function() {
                        var e = (0, C.getURLParameter)("category");
                        null !== e && this.setState({
                            selectedCategories: [e]
                        })
                    }
                }, {
                    key: "componentDidMount",
                    value: function() {
                        var e = this;
                        Promise.all([(0, z.fetchAnalyticStories)(), (0, z.fetchSavedSearches)(), (0, C.getUserPrefModel)(), (0, z.fetchUseCasesCategories)()]).then(function(t) {
                            var a = (0, f.default)(t, 4),
                                n = a[0],
                                l = a[1],
                                r = a[2],
                                o = a[3];
                            e.userPrefModel = r;
                            var i = (0, z.getAnalyticStoriesFromResponse)(n),
                                s = (0, z.getUseCasesFromResponse)(o),
                                u = (0, z.getSavedSearchesFromResponse)(l),
                                d = (0, z.mergeAnalyticStoriesWithSearches)(i, u),
                                c = (0, z.getMetadataInfo)(d) || {},
                                p = {
                                    useCases: s,
                                    analyticStories: d,
                                    isLoading: !1,
                                    annotations: c.annotations
                                };
                            return e.setState(p), d
                        }).catch(function() {
                            e.setState({
                                errorMsg: (0, H._)("Error fetching the analytic stories."),
                                isLoading: !1
                            })
                        }).then(function(t) {
                            return e.setSavedSearchPropertiesAndInUse(t)
                        }).then(function(t) {
                            return e.setBookmarkedStories(t)
                        }).then(function(e) {
                            var t = (0, K.uniqBy)(e, "app").map(function(e) {
                                return e.app
                            }).concat(["DA-ESS-ContentUpdate"]);
                            return Promise.all([e, (0, C.getApps)((0, C.getSearchStringByNames)(t))])
                        }).then(function(t) {
                            var a = (0, f.default)(t, 2),
                                n = a[0],
                                l = a[1],
                                r = l.find(function(e) {
                                    return "DA-ESS-ContentUpdate" === e.name
                                }),
                                o = !1;
                            r || (0, b.normalizeBoolean)(e.userPrefModel.entry.content.get("dontShowESCUModal")) || (o = !0);
                            var i = n.map(function(e) {
                                var t = l.find(function(t) {
                                        return t.name === e.app
                                    }),
                                    a = t && t.content && t.content.label ? t.content.label : e.app;
                                return Object.assign(e, {
                                    appLabel: a
                                })
                            });
                            e.setState((0, u.default)({
                                apps: l.map(function(e) {
                                    return {
                                        name: e.name,
                                        label: e.content.label
                                    }
                                })
                            }, o && {
                                modal: "escu"
                            }, {
                                analyticStories: i
                            }))
                        }), this.fetchAndSetDataModelsDataSources()
                    }
                }, {
                    key: "setSavedSearchPropertiesAndInUse",
                    value: function(e) {
                        var t = this;
                        return new Promise(function(a) {
                            (0, C.fetchRESTURL)("saved/searches", {
                                app: oe.app,
                                owner: "nobody"
                            }, {
                                output_mode: "json",
                                count: 0
                            }).then(function(t) {
                                var n = e.slice().map(function(e) {
                                    return e.searches = e.searches.map(function(e) {
                                        var a = t.entry.find(function(t) {
                                            return e.name === t.name
                                        });
                                        return Object.assign(e, {
                                            label: void 0 !== a ? a.content["action.correlationsearch.label"] : "",
                                            active: void 0 !== a && a.content.is_scheduled && a.content.disabled === !1,
                                            app: void 0 !== a ? a.acl.app : "",
                                            uri: void 0 !== a ? a.links.edit : "",
                                            isCorrelationSearch: void 0 !== a && (0, b.normalizeBoolean)(a.content["action.correlationsearch.enabled"]) === !0
                                        })
                                    }), e.in_use = e.searches.some(function(e) {
                                        return "detection" === e.type && e.active
                                    }), e
                                });
                                a(n)
                            }).catch(function(n) {
                                t.setState({
                                    errorMsg: (0, H._)("Error detecting if analytic stories are in use.") + " " + n
                                }), a(e)
                            })
                        })
                    }
                }, {
                    key: "setBookmarkedStories",
                    value: function(e) {
                        var t = this.getCurrentBookmarks();
                        if (t.length > 0) {
                            var a = e.slice().map(function(e) {
                                return e.bookmarked = Boolean(t.indexOf(e.name) !== -1), e
                            });
                            return a
                        }
                        return e.map(function(e) {
                            return e.bookmarked = !1, e
                        })
                    }
                }, {
                    key: "getFilteredStories",
                    value: function(e, t, a) {
                        var n = arguments.length > 3 && void 0 !== arguments[3] ? arguments[3] : {},
                            l = this.state,
                            r = l.dataModelsSearchesMap,
                            o = l.dataSourcesSearchesMap,
                            i = e;
                        if (a.length > 0) {
                            var s = a.map(function(e) {
                                return e.toLowerCase()
                            });
                            i = i.filter(function(e) {
                                return (0, K.includes)(s, e.category.toLowerCase())
                            })
                        }
                        if (t.length > 0) {
                            var u = t.toLowerCase();
                            i = i.filter(function(e) {
                                return e.category.toLowerCase().includes(u) || e.name.toLowerCase().includes(u) || e.narrative.toLowerCase().includes(u) || e.description.toLowerCase().includes(u) || (0, z.isAnnotationContainedInStory)(e, t)
                            })
                        }
                        if (void 0 !== n.filterApp && "" !== n.filterApp && (i = i.filter(function(e) {
                                return e.app === n.filterApp
                            })), void 0 !== n.filterInUse && "" !== n.filterInUse) {
                            var d = Splunk.util.normalizeBoolean(n.filterInUse);
                            i = i.filter(function(e) {
                                return e.in_use === d
                            })
                        }
                        if (void 0 !== n.filterBookmarked && "" !== n.filterBookmarked) {
                            var f = Splunk.util.normalizeBoolean(n.filterBookmarked);
                            i = i.filter(function(e) {
                                return e.bookmarked === f
                            })
                        }
                        if (void 0 !== n.filterMetadata && n.filterMetadata.length > 0 && (i = i.filter(function(e) {
                                return n.filterMetadata.some(function(t) {
                                    return (0, z.isAnnotationContainedInStory)(e, t)
                                })
                            })), void 0 !== n.filterDataModel && n.filterDataModel.length > 0) {
                            var c = r.get(n.filterDataModel);
                            void 0 === c ? i = [] : c.length > 0 && (i = i.filter(function(e) {
                                return e.searches.some(function(e) {
                                    return c.indexOf(e.name) !== -1
                                })
                            }))
                        }
                        if (void 0 !== n.filterDataSource && n.filterDataSource.length > 0) {
                            var p = o.get(n.filterDataSource);
                            void 0 === p ? i = [] : p.length > 0 && (i = i.filter(function(e) {
                                return e.searches.some(function(e) {
                                    return p.indexOf(e.name) !== -1
                                })
                            }))
                        }
                        return i
                    }
                }, {
                    key: "setSearchTerm",
                    value: function(e) {
                        this.setState({
                            searchTerm: e
                        })
                    }
                }, {
                    key: "getCurrentBookmarks",
                    value: function() {
                        var e = void 0;
                        try {
                            e = this.userPrefModel.entry.content.get("analyticStoryBookmarks") || "[]", e = JSON.parse(e)
                        } catch (t) {
                            e = []
                        }
                        return e
                    }
                }, {
                    key: "getAnalyticStoriesLabel",
                    value: function(e, t) {
                        if (0 === e.length) return "" + (0, H._)("0 Analytic Stories found in the selected categories");
                        var a = t.join(", "),
                            n = 1 === t.length ? (0, H._)("category") + ": " + a : (0, H._)("categories") + ": " + a,
                            l = 1 === e.length ? "" + (0, H._)("Analytic Story found in") : "" + (0, H._)("Analytic Stories found in");
                        return e.length + " " + l + " " + n
                    }
                }, {
                    key: "getUseCaseCards",
                    value: function(e) {
                        var t = this,
                            a = this.state.selectedCategories;
                        return e.map(function(e) {
                            return _.default.createElement(q.default, {
                                key: e.id,
                                id: e.name,
                                name: e.name,
                                description: e.description,
                                icon: e.icon,
                                selected: (0, K.includes)(a, e.name),
                                onClick: t.handleCategoryClick
                            })
                        })
                    }
                }, {
                    key: "handleAnnotationClick",
                    value: function(e, t) {
                        var a = this.state.filterMetadata,
                            n = a.slice();
                        n.indexOf(t) === -1 ? n.push(t) : n.splice(n.indexOf(t), 1), this.updateMetadataState(n)
                    }
                }, {
                    key: "updateMetadataState",
                    value: function(e) {
                        this.setState({
                            filterMetadata: e.slice()
                        })
                    }
                }, {
                    key: "handleCloseESCUModal",
                    value: function() {
                        var e = this.state.optOut;
                        this.userPrefModel.entry.content.set({
                            dontShowESCUModal: e
                        }), this.userPrefModel.save(), this.setState({
                            modal: ""
                        })
                    }
                }, {
                    key: "handleOptOutClick",
                    value: function(e, t) {
                        var a = t.value;
                        this.setState({
                            optOut: !a
                        })
                    }
                }, {
                    key: "fetchSearchContentInfo",
                    value: function(e) {
                        return ue[e] ? Promise.resolve(ue[e]) : new Promise(function(t) {
                            (0, ie.fetchContentInfo)("savedsearch", e, "nobody", oe.app, de).then(function(a) {
                                if (a && a.entry && a.entry.length > 0 && a.entry[0].content && a.entry[0].content.datasets) {
                                    var n = (0, ie.parseDatasets)(a.entry[0].content.datasets);
                                    ue[e] = n, t(n)
                                }
                                t({})
                            }).catch(function() {
                                t({})
                            })
                        })
                    }
                }, {
                    key: "fetchStoryContentInfo",
                    value: function(e) {
                        var t = this;
                        return new Promise(function(a) {
                            var n = e.searches.filter(function(e) {
                                return "detection" === e.type
                            }).map(function(e) {
                                return t.fetchSearchContentInfo(e.name)
                            });
                            Promise.all(n).then(function(n) {
                                var l = (0, z.getMetadataInfo)([e]),
                                    r = l.technologies.map(function(e) {
                                        return {
                                            label: e,
                                            id: e
                                        }
                                    }),
                                    o = n.filter(function(e) {
                                        return e.size > 0
                                    }),
                                    s = o.map(function(e) {
                                        return e.get("sourcetype")
                                    }),
                                    u = o.map(function(e) {
                                        return e.get("datamodel")
                                    }),
                                    d = o.map(function(e) {
                                        return e.get("lookup")
                                    });
                                a({
                                    providingTechnologies: r,
                                    sourcetypes: t.addReadinessToItems("sourcetype", K.unionBy.apply(void 0, (0, i.default)(s).concat(["id"]))),
                                    dataModels: t.addReadinessToItems("datamodel", K.unionBy.apply(void 0, (0, i.default)(u).concat(["id"]))),
                                    lookups: t.addReadinessToItems("lookup", K.unionBy.apply(void 0, (0, i.default)(d).concat(["id"])))
                                })
                            })
                        })
                    }
                }, {
                    key: "addReadinessToItems",
                    value: function(e, t) {
                        return t.map(function(t) {
                            return t.reason = (0, ie.getReasonForReadiness)(e, t.readiness), t
                        })
                    }
                }, {
                    key: "fetchAndSetDataModelsDataSources",
                    value: function() {
                        var e = this;
                        (0, ie.fetchContentInfo)("datamodel", void 0, "nobody", oe.app).then(function(t) {
                            e.setState({
                                dataModels: t.entry.map(function(e) {
                                    return e.name
                                })
                            })
                        }).catch(function() {
                            e.setState({
                                errorMsg: (0, H._)("Error fetching the data models.")
                            })
                        });
                        var t = {
                            output_mode: "json",
                            count: -1
                        };
                        (0, C.fetchRESTURL)("storage/collections/data/dataset_cache", {
                            app: "SA-Utils",
                            owner: "nobody"
                        }, t).then(function(t) {
                            var a = t.filter(function(e) {
                                    return "datamodel" === e.type && e.usedby && e.usedby.savedsearch
                                }).map(function(e) {
                                    return [e.name, e.usedby.savedsearch]
                                }),
                                n = new Map(a);
                            e.setState({
                                dataModelsSearchesMap: n
                            })
                        }).catch(function() {})
                    }
                }, {
                    key: "handleBookmarkClick",
                    value: function(e, t) {
                        var a = t.value,
                            n = this.state.analyticStories,
                            l = this.getCurrentBookmarks();
                        l.indexOf(a) === -1 ? l.push(a) : l = l.filter(function(e) {
                            return e !== a
                        }), this.userPrefModel.entry.content.set({
                            analyticStoryBookmarks: JSON.stringify(l)
                        }), this.userPrefModel.save();
                        var r = n.slice().map(function(e) {
                            return e.name === a && (e.bookmarked = !e.bookmarked), e
                        });
                        this.setState({
                            analyticStories: r
                        })
                    }
                }, {
                    key: "handleMetadataFilterChange",
                    value: function(e, t) {
                        var a = t.values;
                        this.updateMetadataState(a)
                    }
                }, {
                    key: "handleFiltersChange",
                    value: function(e, t) {
                        var a = t.name,
                            n = t.value;
                        this.setState((0, r.default)({}, a, n))
                    }
                }, {
                    key: "handleCategoryClick",
                    value: function(e, t) {
                        var a = t.value,
                            n = this.state.selectedCategories,
                            l = n;
                        (0, K.includes)(l, a) ? this.setState({
                            selectedCategories: (0, K.without)(l, a)
                        }): this.setState({
                            selectedCategories: l.concat(a)
                        })
                    }
                }, {
                    key: "handleSearchChange",
                    value: function(e, t) {
                        var a = t.value;
                        this.setState({
                            searchValue: a
                        }), this.setSearchTerm(a)
                    }
                }, {
                    key: "render",
                    value: function() {
                        var e = this,
                            t = this.state,
                            a = t.errorMsg,
                            n = t.isLoading,
                            l = t.analyticStories,
                            r = t.searchTerm,
                            o = t.selectedCategories,
                            i = t.filterMetadata,
                            s = t.filterApp,
                            u = t.filterDataSource,
                            d = t.filterDataModel,
                            f = t.filterInUse,
                            c = t.filterBookmarked,
                            p = t.useCases,
                            m = t.modal,
                            h = t.optOut,
                            g = t.apps,
                            y = t.annotations,
                            v = t.dataModels,
                            k = t.dataSources,
                            S = t.searchValue,
                            C = t.openDiscoverRecStoriesModal,
                            b = {
                                searchTerm: r,
                                metadata: i,
                                app: s,
                                dataSource: u,
                                dataModel: d,
                                inUse: f,
                                bookmarked: c
                            },
                            E = a.length > 0;
                        if (n) return _.default.createElement(Y.default, {
                            size: "medium",
                            style: se.spinnerStyle
                        });
                        var M = this.getFilteredStories(l, r, o, {
                                filterMetadata: i,
                                filterApp: s,
                                filterDataSource: u,
                                filterDataModel: d,
                                filterInUse: f,
                                filterBookmarked: c
                            }),
                            q = (0, K.uniq)(M.map(function(e) {
                                return e.category
                            })),
                            O = this.getAnalyticStoriesLabel(M, q),
                            A = (0, ne.makeURLfromArgs)("manager", oe.app, "appsremote", {
                                count: 1,
                                query: "Splunk ES Content Update"
                            });
                        return _.default.createElement(_.default.Fragment, null, _.default.createElement(Q.default, {
                            pageTitle: (0, H._)("Use Case Library"),
                            pageDescr: (0, H._)("Explore the Analytic Stories included with Enterprise Security that provide analysis guidance on how to investigate and take actions on threats that ES detects."),
                            descriptionPadding: "0 200px 0 0",
                            border: !0
                        }), E && _.default.createElement(re.default, {
                            fill: !0,
                            type: "error",
                            style: se.marginLeftRight20
                        }, a), _.default.createElement("div", null, _.default.createElement("div", {
                            "data-test": "use-cases-column",
                            style: fe
                        }, _.default.createElement(T.default, {
                            style: se.marginTop20,
                            level: 2
                        }, (0, H._)("Use Cases")), _.default.createElement(V.default, null, this.getUseCaseCards(p))), _.default.createElement("div", {
                            style: ce
                        }, _.default.createElement("div", {
                            style: me
                        }, _.default.createElement(R.default, null, _.default.createElement(R.default.Row, null, _.default.createElement(R.default.Column, null, _.default.createElement(R.default.Row, null, _.default.createElement(R.default.Column, {
                            style: se.noMargin,
                            span: 10,
                            "data-test": "use-case-filters"
                        }, _.default.createElement(ae.default, {
                            apps: g,
                            annotations: y,
                            dataModels: v,
                            dataSources: k,
                            onFilterChanged: this.handleFiltersChange,
                            onMetadataChanged: this.handleMetadataFilterChange,
                            filterMetadata: i,
                            filterInUse: f,
                            filterDataModel: d,
                            filterDataSource: u,
                            filterApp: s,
                            filterBookmarked: c
                        })), _.default.createElement(R.default.Column, {
                            style: pe,
                            span: 2
                        }, _.default.createElement(J.default, {
                            appearance: "search",
                            value: S,
                            placeholder: (0, H._)("filter..."),
                            onChange: this.handleSearchChange,
                            "data-test": "filterText"
                        }))), _.default.createElement(R.default.Row, null, _.default.createElement(R.default.Column, {
                            span: 12,
                            style: he
                        }, O)))))), _.default.createElement("div", null, _.default.createElement(w.default, {
                            filters: b,
                            analyticStories: M,
                            onAnnotationClick: this.handleAnnotationClick,
                            fetchStoryContentInfo: this.fetchStoryContentInfo,
                            handleBookmarkClick: this.handleBookmarkClick
                        })))), _.default.createElement(ee.default, {
                            open: C,
                            onRequestClose: function() {
                                return e.setState({
                                    openDiscoverRecStoriesModal: !1
                                })
                            },
                            onClick: function() {
                                return e.setState({
                                    openDiscoverRecStoriesModal: !1
                                })
                            }
                        }), _.default.createElement(L.default, {
                            onRequestClose: this.handleCloseESCUModal,
                            open: "escu" === m,
                            style: se.modalStyle450
                        }, _.default.createElement(L.default.Header, {
                            title: (0, H._)("ES Content Update Recommended"),
                            onRequestClose: this.handleCloseESCUModal
                        }), _.default.createElement(L.default.Body, null, _.default.createElement(I.default, null, (0, H._)("Download and install the ES Content Update add-on for access to common security analytic stories.")), _.default.createElement(I.default, null, _.default.createElement(x.default, {
                            to: A,
                            openInNewContext: !0
                        }, "Install ES Content Update App from Splunk")), _.default.createElement(I.default, null, _.default.createElement(x.default, {
                            to: "https://splunkbase.splunk.com/app/3449",
                            openInNewContext: !0
                        }, "ES Content Update App on Splunkbase"))), _.default.createElement(L.default.Footer, null, _.default.createElement(N.default, {
                            style: se.floatLeft,
                            onClick: this.handleOptOutClick,
                            selected: h,
                            value: h
                        }, _.default.createElement("span", {
                            style: se.fontSize12
                        }, (0, H._)("Don't show this modal again."))), _.default.createElement(P.default, {
                            onClick: this.handleCloseESCUModal,
                            label: (0, H._)("Close")
                        }))))
                    }
                }]), t
            }(S.Component);
        t.default = ge, e.exports = t.default
    },
    2930: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1461),
            h = n(m),
            g = a(2178),
            y = n(g),
            v = a(1652),
            k = n(v);
        a(57);
        var S = function(e) {
                return {
                    width: 180,
                    minWidth: 100,
                    marginBottom: 10,
                    background: e ? "#ECF8FF" : "#FFF"
                }
            },
            _ = {
                fontWeight: "bold"
            },
            C = {
                textAlign: "center"
            },
            b = function(e) {
                function t() {
                    return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
                }
                return (0, f.default)(t, e), (0, i.default)(t, [{
                    key: "render",
                    value: function() {
                        var e = this.props,
                            t = e.id,
                            a = e.description,
                            n = e.onClick,
                            l = e.selected,
                            r = e.name,
                            o = e.icon,
                            i = {
                                height: 72,
                                width: 72,
                                marginTop: -111
                            },
                            s = {
                                height: 76,
                                width: 76,
                                borderRadius: "50%",
                                display: "inline-block",
                                border: "solid 1px " + (l ? "#007ABD" : "#ffffff")
                            };
                        return p.default.createElement(k.default, {
                            content: a,
                            defaultPlacement: "right"
                        }, p.default.createElement(y.default, {
                            style: S(l),
                            value: t,
                            onClick: n,
                            selected: l
                        }, p.default.createElement(y.default.Header, {
                            title: r,
                            truncateTitle: !1,
                            style: _
                        }), p.default.createElement(y.default.Body, {
                            style: C
                        }, p.default.createElement("div", {
                            style: s
                        }), p.default.createElement("img", {
                            src: o,
                            style: i,
                            alt: r
                        }))))
                    }
                }]), t
            }(c.Component);
        b.propTypes = {
            name: h.default.string.isRequired,
            id: h.default.string.isRequired,
            description: h.default.string.isRequired,
            icon: h.default.string.isRequired,
            selected: h.default.bool.isRequired,
            onClick: h.default.func.isRequired
        }, t.default = b, e.exports = t.default
    },
    2931: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1),
            h = a(1352),
            g = a(888),
            y = a(2932),
            v = n(y),
            k = a(1621),
            S = n(k),
            _ = a(1909),
            C = n(_),
            b = a(1461),
            E = n(b),
            R = a(1847),
            M = n(R),
            q = a(1814),
            O = n(q),
            w = a(1652),
            A = n(w),
            T = a(1859),
            D = n(T),
            L = a(1682),
            U = n(L),
            I = a(1701),
            B = n(I),
            x = a(1626);
        a(57);
        var F = function(e) {
            function t(e, a) {
                (0, r.default)(this, t);
                var n = (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, a));
                return n.handleSort = n.handleSort.bind(n), n.state = {
                    sortKey: "name",
                    sortDir: "asc"
                }, n
            }
            return (0, f.default)(t, e), (0, i.default)(t, [{
                key: "getExpansionRow",
                value: function(e) {
                    var t = this.props,
                        a = t.onAnnotationClick,
                        n = t.fetchStoryContentInfo;
                    return p.default.createElement(C.default.Row, {
                        key: e.name + "-expansion"
                    }, p.default.createElement(C.default.Cell, {
                        style: x.noBorderTop,
                        colSpan: 7
                    }, p.default.createElement(v.default, {
                        anStory: e,
                        onAnnotationClick: a,
                        fetchStoryContentInfo: n
                    })))
                }
            }, {
                key: "getStoryInUseComponent",
                value: function(e) {
                    return void 0 === e.in_use ? p.default.createElement(D.default, null) : p.default.createElement(A.default, {
                        content: e.in_use ? (0, m._)("Story is in use") : (0, m._)("No searches are active")
                    }, e.in_use ? p.default.createElement(O.default, {
                        "data-test": "in-use",
                        screenReaderText: ""
                    }) : p.default.createElement(M.default, {
                        "data-test": "not-in-use",
                        screenReaderText: ""
                    }))
                }
            }, {
                key: "sortAnalyticStoriesWithKey",
                value: function(e, t, a) {
                    var n = "asc" === a ? 1 : -1;
                    return e.sort(function(e, a) {
                        return e[t] < a[t] ? -1 * n : e[t] > a[t] ? 1 * n : 0
                    })
                }
            }, {
                key: "handleSort",
                value: function(e, t) {
                    var a = t.sortKey,
                        n = this.state.sortDir,
                        l = this.state.sortKey,
                        r = l === a ? n : "none",
                        o = "asc" === r ? "desc" : "asc";
                    this.setState({
                        sortKey: a,
                        sortDir: o
                    })
                }
            }, {
                key: "renderAnalyticStoryRow",
                value: function(e) {
                    var t = this.props.handleBookmarkClick,
                        a = e.name,
                        n = (0, h.makeURLfromArgs)("app", g.app, "ess_analytic_story_details", {
                            analytic_story: a
                        });
                    return p.default.createElement(C.default.Row, {
                        key: e.id,
                        expansionRow: this.getExpansionRow(e)
                    }, p.default.createElement(C.default.Cell, {
                        align: "center",
                        "data-test": "in-use-section",
                        "data-test-value": e.in_use
                    }, this.getStoryInUseComponent(e)), p.default.createElement(C.default.Cell, {
                        data: e,
                        "data-test": "analytic-story-section",
                        "data-test-value": a
                    }, p.default.createElement(S.default, {
                        to: n
                    }, a)), p.default.createElement(C.default.Cell, {
                        data: e,
                        "data-test": "use-case-section",
                        "data-test-value": e.category
                    }, e.category), p.default.createElement(C.default.Cell, {
                        "data-test": "description-section"
                    }, e.description), p.default.createElement(C.default.Cell, {
                        "data-test": "app-section"
                    }, e.appLabel), p.default.createElement(C.default.Cell, {
                        "data-test": "last-updated-section"
                    }, B.default.newSplunkTime({
                        time: e.last_updated
                    }).format("ll")), p.default.createElement(C.default.Cell, {
                        "data-test": "bookmarked-section",
                        "data-test-value": e.bookmarked
                    }, void 0 !== e.bookmarked && p.default.createElement(U.default, {
                        key: e.id,
                        value: e.name,
                        onClick: t,
                        selected: e.bookmarked,
                        selectedLabel: (0, m._)("Bookmark enabled"),
                        unselectedLabel: (0, m._)("Bookmark disabled"),
                        appearance: "toggle",
                        size: "small"
                    })))
                }
            }, {
                key: "render",
                value: function() {
                    var e = this,
                        t = this.state,
                        a = t.sortKey,
                        n = t.sortDir,
                        l = this.props,
                        r = l.analyticStories,
                        o = l.filters,
                        i = o.searchTerm,
                        s = o.metadata,
                        u = o.app,
                        d = o.dataSource,
                        f = o.dataModel,
                        c = o.inUse,
                        h = o.bookmarked,
                        g = this.sortAnalyticStoriesWithKey(r, a, n);
                    return p.default.createElement(C.default, {
                        stripeRows: !0,
                        rowExpansion: "single",
                        innerStyle: x.tableStyle,
                        "data-test-filter-metadata": s.join(","),
                        "data-test-filter-app": u,
                        "data-test-filter-datasource": d,
                        "data-test-filter-datamodel": f,
                        "data-test-filter-inuse": c,
                        "data-test-filter-bookmarked": h,
                        "data-test-search-term": i
                    }, p.default.createElement(C.default.Head, null, p.default.createElement(C.default.HeadCell, {
                        width: 30
                    }, (0, m._)("In use")), p.default.createElement(C.default.HeadCell, {
                        width: 180,
                        onSort: this.handleSort,
                        sortKey: "name",
                        sortDir: "name" === a ? n : "none"
                    }, (0, m._)("Analytic Story")), p.default.createElement(C.default.HeadCell, {
                        width: 140,
                        onSort: this.handleSort,
                        sortKey: "category",
                        sortDir: "category" === a ? n : "none"
                    }, (0, m._)("Use Case")), p.default.createElement(C.default.HeadCell, null, (0, m._)("Description")), p.default.createElement(C.default.HeadCell, {
                        width: 110,
                        onSort: this.handleSort,
                        sortKey: "app",
                        sortDir: "app" === a ? n : "none"
                    }, (0, m._)("App")), p.default.createElement(C.default.HeadCell, {
                        width: 90,
                        onSort: this.handleSort,
                        sortKey: "last_updated",
                        sortDir: "last_updated" === a ? n : "none"
                    }, (0, m._)("Last Updated")), p.default.createElement(C.default.HeadCell, {
                        width: 90,
                        onSort: this.handleSort,
                        sortKey: "bookmarked",
                        sortDir: "bookmarked" === a ? n : "none"
                    }, (0, m._)("Bookmark"))), p.default.createElement(C.default.Body, null, g.map(function(t) {
                        return e.renderAnalyticStoryRow(t)
                    })))
                }
            }]), t
        }(c.Component);
        F.propTypes = {
            analyticStories: E.default.arrayOf(E.default.shape({
                name: E.default.string.isRequired,
                description: E.default.string.isRequired,
                app: E.default.string.isRequired,
                category: E.default.string.isRequired,
                in_use: E.default.bool,
                bookmarked: E.default.bool,
                last_updated: E.default.string.isRequired,
                annotations: E.default.arrayOf(E.default.shape({
                    name: E.default.string.isRequired,
                    items: E.default.arrayOf(E.default.string).isRequired
                })).isRequired,
                searches: E.default.arrayOf(E.default.shape({
                    type: E.default.string.isRequired,
                    name: E.default.string.isRequired
                })).isRequired
            }).isRequired).isRequired,
            onAnnotationClick: E.default.func.isRequired,
            fetchStoryContentInfo: E.default.func.isRequired,
            handleBookmarkClick: E.default.func.isRequired,
            filters: E.default.shape({
                searchTerm: E.default.string.isRequired,
                metadata: E.default.arrayOf(E.default.string).isRequired,
                app: E.default.string.isRequired,
                dataSource: E.default.string.isRequired,
                dataModel: E.default.string.isRequired,
                inUse: E.default.string.isRequired,
                bookmarked: E.default.string.isRequired
            }).isRequired
        }, t.default = F, e.exports = t.default
    },
    2932: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1461),
            h = n(m),
            g = a(1673),
            y = n(g),
            v = a(1),
            k = a(1674),
            S = n(k),
            _ = a(1621),
            C = n(_),
            b = a(1352),
            E = a(888),
            R = a(2933),
            M = n(R),
            q = a(1652),
            O = n(q),
            w = a(1619),
            A = n(w),
            T = a(1620),
            D = n(T),
            L = a(1847),
            U = n(L),
            I = a(1814),
            B = n(I),
            x = a(2934),
            F = n(x);
        a(57);
        var P = function(e) {
            function t(e, a) {
                (0, r.default)(this, t);
                var n = (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, a));
                return n.state = {
                    dataModels: [],
                    providingTechnologies: [],
                    sourcetypes: [],
                    lookups: [],
                    loading: !1
                }, n
            }
            return (0, f.default)(t, e), (0, i.default)(t, [{
                key: "componentDidMount",
                value: function() {
                    var e = this.props.anStory;
                    this.fetchData(e)
                }
            }, {
                key: "componentDidUpdate",
                value: function(e) {
                    var t = this.props.anStory;
                    t.id !== e.anStory.id && this.fetchData(t)
                }
            }, {
                key: "fetchData",
                value: function(e) {
                    var t = this,
                        a = this.props.fetchStoryContentInfo;
                    this.setState({
                        loading: !0
                    }), a(e).then(function(e) {
                        t.setState({
                            providingTechnologies: e.providingTechnologies,
                            sourcetypes: e.sourcetypes,
                            dataModels: e.dataModels,
                            lookups: e.lookups,
                            loading: !1
                        })
                    })
                }
            }, {
                key: "genEditLink",
                value: function(e) {
                    if (e.isCorrelationSearch) {
                        var t = (0, b.makeURLfromArgs)("app", E.app, "correlation_search_edit", {
                            search: e.name
                        });
                        return p.default.createElement(C.default, {
                            to: t
                        }, (0, v._)("edit"), " ")
                    }
                    var a = (0, b.makeURLfromArgs)("manager", E.app, "saved", "searches", e.name, {
                        search: e.name,
                        app: e.app,
                        uri: e.uri,
                        action: "edit"
                    });
                    return p.default.createElement(C.default, {
                        to: a
                    }, (0, v._)("edit saved search"), " ")
                }
            }, {
                key: "render",
                value: function() {
                    var e = this,
                        t = this.props,
                        a = t.anStory,
                        n = t.onAnnotationClick,
                        l = this.state,
                        r = l.sourcetypes,
                        o = l.dataModels,
                        i = l.providingTechnologies,
                        s = l.lookups,
                        u = l.loading,
                        d = {
                            padding: 5
                        },
                        f = {
                            borderStyle: "solid",
                            paddingRight: 5,
                            paddingLeft: 5,
                            borderWidth: .5,
                            borderColor: "#C3CBD4"
                        },
                        c = (0, v._)("See all %d Lookups").replace("%d", s.length),
                        m = (0, v._)("See all %d Sourcetypes").replace("%d", r.length),
                        h = (0, v._)("See all %d Data Models").replace("%d", o.length),
                        g = (0, v._)("See all %d Data Sources").replace("%d", i.length),
                        k = a.searches.filter(function(e) {
                            return "detection" === e.type
                        }).map(function(t) {
                            return p.default.createElement(S.default.Item, {
                                "data-test-value": t.active,
                                "data-test-search": t.name,
                                key: t.name
                            }, p.default.createElement(O.default, {
                                content: t.active ? (0, v._)("Search is active") : (0, v._)("Search is not active")
                            }, t.active ? p.default.createElement(B.default, {
                                screenReaderText: ""
                            }) : p.default.createElement(U.default, {
                                screenReaderText: ""
                            })), " ", " ", t.name, " - ", e.genEditLink(t))
                        });
                    return p.default.createElement(y.default, {
                        style: f,
                        gutter: 0
                    }, p.default.createElement(y.default.Row, null, p.default.createElement(y.default.Column, {
                        style: d,
                        span: 6
                    }, p.default.createElement(O.default, {
                        content: (0, v._)("See all the searches by clicking on the Analytic Story name.")
                    }, p.default.createElement(A.default, null, (0, v._)("Detection Searches"))), 0 === k.length ? p.default.createElement(D.default, null, (0, v._)("No items found.")) : p.default.createElement(S.default, {
                        "data-test": "detection-searches-section"
                    }, k)), p.default.createElement(F.default, {
                        heading: (0, v._)("Recommended Data Sources"),
                        loading: u,
                        items: i,
                        anchorButtonLabel: g,
                        modalTitle: (0, v._)("All Data Sources"),
                        testString: "recommended-data-sources-section"
                    }), p.default.createElement(F.default, {
                        heading: (0, v._)("Sourcetypes"),
                        loading: u,
                        items: r,
                        anchorButtonLabel: m,
                        modalTitle: (0, v._)("All Sourcetypes"),
                        testString: "sourcetypes-section"
                    }), p.default.createElement(F.default, {
                        heading: (0, v._)("Data Models"),
                        loading: u,
                        items: o,
                        anchorButtonLabel: h,
                        modalTitle: (0, v._)("All Data Models"),
                        testString: "data-models-section"
                    }), p.default.createElement(F.default, {
                        heading: (0, v._)("Lookups"),
                        loading: u,
                        items: s,
                        anchorButtonLabel: c,
                        modalTitle: (0, v._)("All Lookups"),
                        testString: "lookups-section"
                    })), p.default.createElement(y.default.Row, null, p.default.createElement(y.default.Column, {
                        style: d,
                        span: 12,
                        "data-test": "framework-mapping-section"
                    }, p.default.createElement(A.default, null, (0, v._)("Framework Mapping")), p.default.createElement(M.default, {
                        data: a.annotations,
                        onItemClick: n
                    }))))
                }
            }]), t
        }(c.Component);
        P.propTypes = {
            anStory: h.default.shape({
                id: h.default.string.isRequired,
                annotations: h.default.arrayOf(h.default.shape({
                    name: h.default.string.isRequired,
                    items: h.default.arrayOf(h.default.string).isRequired
                })).isRequired,
                searches: h.default.arrayOf(h.default.shape({
                    type: h.default.string.isRequired,
                    name: h.default.string.isRequired,
                    isCorrelationSearch: h.default.bool.isRequired
                })).isRequired
            }).isRequired,
            onAnnotationClick: h.default.func.isRequired,
            fetchStoryContentInfo: h.default.func.isRequired
        }, t.default = P, e.exports = t.default
    },
    2933: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(2161),
            h = n(m),
            g = a(1461),
            y = n(g);
        a(57);
        var v = function(e) {
            function t() {
                return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
            }
            return (0, f.default)(t, e), (0, i.default)(t, [{
                key: "render",
                value: function() {
                    var e = this.props,
                        t = e.data,
                        a = e.onItemClick;
                    return t.map(function(e) {
                        return p.default.createElement(h.default, {
                            key: e.name,
                            name: e.name,
                            label: e.label || e.name,
                            color: e.color,
                            items: e.items,
                            onItemClick: a,
                            clickable: !0
                        })
                    })
                }
            }]), t
        }(c.Component);
        v.propTypes = {
            data: y.default.arrayOf(y.default.shape({
                color: y.default.string,
                name: y.default.string.isRequired,
                label: y.default.string.isRequired,
                items: y.default.arrayOf(y.default.string).isRequired
            })).isRequired,
            onItemClick: y.default.func.isRequired
        }, t.default = v, e.exports = t.default
    },
    2934: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1461),
            h = n(m),
            g = a(1673),
            y = n(g),
            v = a(1),
            k = a(1619),
            S = n(k),
            _ = a(1617),
            C = n(_),
            b = a(1620),
            E = n(b),
            R = a(2203),
            M = n(R);
        a(57);
        var q = {
                padding: 5
            },
            O = function(e) {
                function t() {
                    return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
                }
                return (0, f.default)(t, e), (0, i.default)(t, [{
                    key: "render",
                    value: function() {
                        var e = this.props,
                            t = e.heading,
                            a = e.loading,
                            n = e.items,
                            l = e.anchorButtonLabel,
                            r = e.modalTitle,
                            o = e.testString;
                        return p.default.createElement(y.default.Column, {
                            style: q,
                            span: 2,
                            "data-test": o
                        }, p.default.createElement(S.default, {
                            level: 3
                        }, t), a && p.default.createElement(C.default, {
                            size: "medium"
                        }), !a && 0 === n.length && p.default.createElement(E.default, null, (0, v._)("No items found.")), p.default.createElement(M.default, {
                            items: n,
                            anchorButtonLabel: l,
                            modalTitle: r
                        }))
                    }
                }]), t
            }(c.Component);
        O.defaultProps = {
            testString: "expanded-row-section"
        }, O.propTypes = {
            heading: h.default.string.isRequired,
            loading: h.default.bool.isRequired,
            anchorButtonLabel: h.default.string.isRequired,
            modalTitle: h.default.string.isRequired,
            items: h.default.arrayOf(h.default.shape({
                id: h.default.string.isRequired,
                label: h.default.string.isRequired,
                readiness: h.default.number
            })).isRequired,
            testString: h.default.string
        }, t.default = O, e.exports = t.default
    },
    2935: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1461),
            h = n(m),
            g = a(1620),
            y = n(g),
            v = a(1633),
            k = n(v),
            S = a(1628),
            _ = n(S),
            C = a(1),
            b = a(1626);
        a(57);
        var E = function(e) {
            function t() {
                return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
            }
            return (0, f.default)(t, e), (0, i.default)(t, [{
                key: "render",
                value: function() {
                    var e = this.props,
                        t = e.onRequestClose,
                        a = e.open,
                        n = e.onClick;
                    return p.default.createElement(k.default, {
                        onRequestClose: t,
                        open: a,
                        style: b.modalStyle750
                    }, p.default.createElement(k.default.Header, {
                        title: (0, C._)("Discover Recommended Stories Wizard"),
                        onRequestClose: t
                    }), p.default.createElement(k.default.Body, null, p.default.createElement(y.default, null, (0, C._)("ES will be able to identify your ingested data and recommend stories you should review and determine if they apply and decide if you want to monitor in your environment."))), p.default.createElement(k.default.Footer, null, p.default.createElement(_.default, {
                        appearance: "primary",
                        onClick: n,
                        label: (0, C._)("Close")
                    })))
                }
            }]), t
        }(c.Component);
        E.propTypes = {
            open: h.default.bool.isRequired,
            onClick: h.default.func.isRequired,
            onRequestClose: h.default.func.isRequired
        }, t.default = E, e.exports = t.default
    },
    2936: function(e, t, a) {
        "use strict";

        function n(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        Object.defineProperty(t, "__esModule", {
            value: !0
        });
        var l = a(864),
            r = n(l),
            o = a(865),
            i = n(o),
            s = a(869),
            u = n(s),
            d = a(870),
            f = n(d),
            c = a(1453),
            p = n(c),
            m = a(1461),
            h = n(m),
            g = a(1),
            y = a(1703),
            v = n(y),
            k = a(1679),
            S = n(k),
            _ = a(1673),
            C = n(_);
        a(57);
        var b = {
                width: "100%"
            },
            E = function(e) {
                function t() {
                    return (0, r.default)(this, t), (0, u.default)(this, (t.__proto__ || Object.getPrototypeOf(t)).apply(this, arguments))
                }
                return (0, f.default)(t, e), (0, i.default)(t, [{
                    key: "getMetadataFilterSelect",
                    value: function() {
                        var e = this.props,
                            t = e.annotations,
                            a = e.filterMetadata,
                            n = e.onMetadataChanged,
                            l = t.reduce(function(e, t) {
                                return e.push(p.default.createElement(S.default.Heading, {
                                    key: t.name,
                                    level: 2
                                }, t.label)), e.push(t.items.map(function(e) {
                                    return p.default.createElement(S.default.Option, {
                                        key: e,
                                        label: e,
                                        value: e
                                    })
                                })), e
                            }, []);
                        return p.default.createElement(S.default, {
                            style: b,
                            inline: !0,
                            values: a,
                            compact: !0,
                            name: "filterMetadata",
                            onChange: n,
                            placeholder: (0, g._)("Framework Mapping: All"),
                            "data-test": "filterMetadata"
                        }, l)
                    }
                }, {
                    key: "getAppFilterSelect",
                    value: function() {
                        var e = this.props,
                            t = e.filterApp,
                            a = e.onFilterChanged,
                            n = e.apps;
                        return p.default.createElement(v.default, {
                            style: b,
                            prefixLabel: (0, g._)("App"),
                            name: "filterApp",
                            value: t,
                            onChange: a,
                            "data-test": "filterApp"
                        }, p.default.createElement(v.default.Option, {
                            key: "all",
                            label: (0, g._)("All"),
                            value: ""
                        }), n.map(function(e) {
                            return p.default.createElement(v.default.Option, {
                                key: e.name,
                                label: e.label,
                                value: e.name
                            })
                        }))
                    }
                }, {
                    key: "getDataSourceFilterSelect",
                    value: function() {
                        var e = this.props,
                            t = e.filterDataSource,
                            a = e.onFilterChanged,
                            n = e.dataSources;
                        return p.default.createElement(v.default, {
                            style: b,
                            prefixLabel: (0, g._)("Data Source"),
                            name: "filterDataSource",
                            value: t,
                            onChange: a,
                            "data-test": "filterDataSource",
                            filter: !0
                        }, p.default.createElement(v.default.Option, {
                            key: "all",
                            label: (0, g._)("All"),
                            value: ""
                        }), n.map(function(e) {
                            return p.default.createElement(v.default.Option, {
                                key: e,
                                label: e,
                                value: e
                            })
                        }))
                    }
                }, {
                    key: "getDataModelFilterSelect",
                    value: function() {
                        var e = this.props,
                            t = e.filterDataModel,
                            a = e.onFilterChanged,
                            n = e.dataModels;
                        return p.default.createElement(v.default, {
                            style: b,
                            prefixLabel: (0, g._)("Data Model"),
                            name: "filterDataModel",
                            value: t,
                            onChange: a,
                            "data-test": "filterDataModel",
                            filter: !0
                        }, p.default.createElement(v.default.Option, {
                            key: "all",
                            label: (0, g._)("All"),
                            value: ""
                        }), n.map(function(e) {
                            return p.default.createElement(v.default.Option, {
                                key: e,
                                label: e,
                                value: e
                            })
                        }))
                    }
                }, {
                    key: "getInUseFilterSelect",
                    value: function() {
                        var e = this.props,
                            t = e.filterInUse,
                            a = e.onFilterChanged;
                        return p.default.createElement(v.default, {
                            style: b,
                            prefixLabel: (0, g._)("In Use"),
                            name: "filterInUse",
                            value: t,
                            onChange: a,
                            "data-test": "filterInUse"
                        }, p.default.createElement(v.default.Option, {
                            key: "all",
                            label: (0, g._)("All"),
                            value: ""
                        }), p.default.createElement(v.default.Option, {
                            key: "true",
                            label: (0, g._)("True"),
                            value: "true"
                        }), p.default.createElement(v.default.Option, {
                            key: "false",
                            label: (0, g._)("False"),
                            value: "false"
                        }))
                    }
                }, {
                    key: "getBookmarkedFilterSelect",
                    value: function() {
                        var e = this.props,
                            t = e.filterBookmarked,
                            a = e.onFilterChanged;
                        return p.default.createElement(v.default, {
                            style: b,
                            prefixLabel: (0, g._)("Bookmarked"),
                            name: "filterBookmarked",
                            value: t,
                            onChange: a,
                            "data-test": "filterBookmarked"
                        }, p.default.createElement(v.default.Option, {
                            key: "all",
                            label: (0, g._)("All"),
                            value: ""
                        }), p.default.createElement(v.default.Option, {
                            key: "true",
                            label: (0, g._)("True"),
                            value: "true"
                        }), p.default.createElement(v.default.Option, {
                            key: "false",
                            label: (0, g._)("False"),
                            value: "false"
                        }))
                    }
                }, {
                    key: "render",
                    value: function() {
                        return p.default.createElement(C.default, {
                            gutter: 8
                        }, p.default.createElement(C.default.Row, null, p.default.createElement(C.default.Column, {
                            span: 2.4
                        }, this.getMetadataFilterSelect()), p.default.createElement(C.default.Column, {
                            span: 2.4
                        }, this.getDataModelFilterSelect()), p.default.createElement(C.default.Column, {
                            span: 2.4
                        }, this.getAppFilterSelect()), p.default.createElement(C.default.Column, {
                            span: 2.4
                        }, this.getInUseFilterSelect()), p.default.createElement(C.default.Column, {
                            span: 2.4
                        }, this.getBookmarkedFilterSelect())))
                    }
                }]), t
            }(c.Component);
        E.propTypes = {
            apps: h.default.arrayOf(h.default.shape({
                name: h.default.string.isRequired,
                label: h.default.string.isRequired
            })).isRequired,
            annotations: h.default.arrayOf(h.default.shape({
                name: h.default.string.isRequired,
                label: h.default.string.isRequired,
                items: h.default.arrayOf(h.default.string).isRequired
            })).isRequired,
            dataModels: h.default.arrayOf(h.default.string).isRequired,
            dataSources: h.default.arrayOf(h.default.string).isRequired,
            onFilterChanged: h.default.func.isRequired,
            onMetadataChanged: h.default.func.isRequired,
            filterMetadata: h.default.arrayOf(h.default.string).isRequired,
            filterInUse: h.default.string.isRequired,
            filterDataModel: h.default.string.isRequired,
            filterDataSource: h.default.string.isRequired,
            filterApp: h.default.string.isRequired,
            filterBookmarked: h.default.string.isRequired
        }, t.default = E, e.exports = t.default
    }
});
