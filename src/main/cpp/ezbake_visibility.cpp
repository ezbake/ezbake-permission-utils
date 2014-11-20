/*   Copyright (C) 2013-2014 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include "ezbake_visibility.hpp"
#include "ezbake_visibility.h" // C API

#include <cctype>

#include <algorithm>
#include <exception>
#include <set>
#include <stdexcept>
#include <string>

#include "boost/algorithm/string/classification.hpp"
#include "boost/algorithm/string/replace.hpp"
#include "boost/algorithm/string/split.hpp"
#include "boost/lexical_cast.hpp"

#pragma GCC diagnostic ignored "-Wconversion"
#include "boost/spirit/include/qi.hpp"
#pragma GCC diagnostic warning "-Wconversion"

#include "boost/spirit/include/phoenix.hpp"
#include "boost/spirit/include/phoenix_operator.hpp"
#include "boost/variant/recursive_wrapper.hpp"

#include "exception_to_error_string.hpp"

using std::invalid_argument;
using std::remove_if;
using std::set;
using std::string;

using boost::apply_visitor;
using boost::lexical_cast;
using boost::recursive_wrapper;
using boost::static_visitor;
using boost::variant;

using boost::algorithm::is_any_of;
using boost::algorithm::replace_all;
using boost::algorithm::split;

using boost::phoenix::construct;

using boost::spirit::qi::_1;
using boost::spirit::qi::_2;
using boost::spirit::qi::_val;
using boost::spirit::qi::alpha;
using boost::spirit::qi::digit;
using boost::spirit::qi::expectation_failure;
using boost::spirit::qi::grammar;
using boost::spirit::qi::lexeme;
using boost::spirit::qi::phrase_parse;
using boost::spirit::qi::rule;
using boost::spirit::qi::space;
using boost::spirit::qi::space_type;

namespace {
    const string TRUE_REPLACE = "ezbTezb";
    const string FALSE_REPLACE = "ezbFezb";

    struct op_or {};
    struct op_and {};
    struct op_not {};

    template<typename tag> struct unop;
    template<typename tag> struct binop;

    typedef variant<
            string,
            recursive_wrapper<unop<op_not>>,
            recursive_wrapper<binop<op_and>>,
            recursive_wrapper<binop<op_or>>> expr;

    template<typename tag>
    struct unop {
        explicit unop(const expr &o): oper1(o) {}
        expr oper1;
    };

    template<typename tag>
    struct binop {
        binop(const expr &l, const expr &r): oper1(l), oper2(r) {}
        expr oper1, oper2;
    };

    class eval: public static_visitor<bool> {
    public:
        bool operator()(const string &v) const {
            if (v == TRUE_REPLACE) {
                return true;
            } else if (v == FALSE_REPLACE) {
                return false;
            }

            return lexical_cast<bool>(v);
        }

        bool operator()(const binop<op_and> &b) const {
            return recurse(b.oper1) && recurse(b.oper2);
        }

        bool operator()(const binop<op_or> &b) const {
            return recurse(b.oper1) || recurse(b.oper2);
        }

        bool operator()(const unop<op_not> &u) const {
            return !recurse(u.oper1);
        }

    private:
        template<typename T>
        bool recurse(const T &v) const {
            return apply_visitor(*this, v);
        }
    };

    bool evaluate(const expr &e) {
        return apply_visitor(eval(), e);
    }

    template<typename Iterator, typename Skipper = space_type>
    class parser : public grammar<Iterator, expr(), Skipper>
    {
    public:
        parser() : parser::base_type(expr_) {
            expr_ = or_.alias();

            or_ = (and_ >> '|'  >> or_ )[
                _val = construct<binop<op_or>>(_1, _2)] | and_[_val = _1];

            and_ = (not_ >> '&' >> and_)[
                _val = construct<binop<op_and>>(_1, _2)] | not_[_val = _1];

            not_ = ('!' > simple_)[_val = construct<unop<op_not>>(_1)] |
                simple_[_val = _1];

            simple_ = (('(' > expr_ > ')') | var_);
            var_ = lexeme[+(alpha | digit)];

            BOOST_SPIRIT_DEBUG_NODE(expr_);
            BOOST_SPIRIT_DEBUG_NODE(or_);
            BOOST_SPIRIT_DEBUG_NODE(and_);
            BOOST_SPIRIT_DEBUG_NODE(not_);
            BOOST_SPIRIT_DEBUG_NODE(simple_);
            BOOST_SPIRIT_DEBUG_NODE(var_);
        }

    private:
        rule<Iterator, string(), Skipper> var_;
        rule<Iterator, expr(), Skipper> not_, and_, or_, simple_, expr_;
    };

    struct MarkingsComparator
    {
        bool operator()(const string &s1, const string &s2) {
            return s1.length() >= s2.length();
        }
    };

    typedef set<string, MarkingsComparator> MarkingsSet;

    MarkingsSet get_markings_from_expression(const string &expression) {
        MarkingsSet markings;
        set<string> splits;
        string expr_no_whitespace = expression;

        remove_if(
                expr_no_whitespace.begin(), expr_no_whitespace.end(),
                ::isspace);

        split(splits, expr_no_whitespace, is_any_of(";|&!^()"));

        auto splits_iter = splits.begin();
        for (; splits_iter != splits.end(); ++splits_iter) {
            if (!splits_iter->empty()) {
                markings.insert(*splits_iter);
            }
        }

        return markings;
    }

    string vis_auth_to_parsable(
            const set<string> &auths,
            const string &vis_expr) {
        string parsable = vis_expr;

        MarkingsSet markings = get_markings_from_expression(vis_expr);
        auto markingsIter = markings.begin();
        for (; markingsIter != markings.end(); ++markingsIter) {
            if (auths.count(*markingsIter) == 1) {
                replace_all(parsable, *markingsIter, TRUE_REPLACE);
            } else {
                replace_all(parsable, *markingsIter, FALSE_REPLACE);
            }
        }

        if (parsable.empty() || parsable[parsable.size() - 1] != ';') {
            parsable += ';';
        }

        return parsable;
    }
}

bool ezbake::evaluate_visibility_expression(
        const set<string> &auths,
        const string &vis_expr) {
    typedef string::const_iterator iter;

    if (vis_expr.empty()) {
        return true; // No visibility expression means a match to any auths
    }

    if (auths.empty()) {
        return false; // There is a visibility expression but no auths
    }

    const string parsable = vis_auth_to_parsable(auths, vis_expr);

    auto f = parsable.begin();
    auto l = parsable.end();
    parser<iter> p;
    try {
        expr parsed;
        bool ok = phrase_parse(f, l, p > ';', space, parsed);

        if (!ok) {
            throw invalid_argument("Could not parse expression");
        }

        return evaluate(parsed);
    } catch (const expectation_failure<iter> &e) {
        throw invalid_argument(
                string("Parse expectation failure at ") +
                string(e.first, e.last));
    }

    if (f != l) {
        throw invalid_argument(
                string("Could not parse entire expression. Unparsed: ") +
                string(f, l));
    }

    return false;
}

bool ezbake_evaluate_visibility_expression(
        const char *auths[],
        size_t auths_length,
        const char * const vis_expr,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(false, {
        string vis_expr_str;
        if (vis_expr != NULL) {
            vis_expr_str = vis_expr;
        }

        set<string> auths_set;
        for (size_t i = 0; i < auths_length; ++i) {
            auths_set.insert(auths[i]);
        }

        return ezbake::evaluate_visibility_expression(auths_set, vis_expr_str);
    })
}

