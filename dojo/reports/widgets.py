import abc
import json
from collections import OrderedDict

from django import forms
from django.forms import Widget
from django.forms.utils import flatatt
from django.http import QueryDict
from django.template.loader import render_to_string
from django.utils.encoding import force_str
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from dojo.filters import (
    EndpointFilter,
    EndpointFilterWithoutObjectLookups,
    ReportFindingFilter,
    ReportFindingFilterWithoutObjectLookups,
)
from dojo.forms import CustomReportOptionsForm
from dojo.models import Endpoint, Finding
from dojo.utils import get_page_items, get_system_setting, get_words_for_field

"""
Widgets are content sections that can be included on reports.  The report builder will allow any number of widgets
 to be included.  Each widget will provide a set of options, reporesented by form elements, to be included.
"""


class CustomReportJsonForm(forms.Form):
    json = forms.CharField()

    def clean_json(self):
        jdata = self.cleaned_data["json"]
        try:
            json.loads(jdata)
        except:
            msg = "Invalid data in json"
            raise forms.ValidationError(msg)
        return jdata


class CoverPageForm(forms.Form):
    heading = forms.CharField(max_length=200, required=False, help_text="The main report heading.")
    sub_heading = forms.CharField(max_length=200, required=False, help_text="The report sub heading.")
    meta_info = forms.CharField(max_length=200, required=False, help_text="Additional metadata for this report.")

    class Meta:
        exclude = []


class TableOfContentsForm(forms.Form):
    heading = forms.CharField(max_length=200, required=False, initial="Table of Contents")

    class Meta:
        exclude = []


class Div(Widget):
    def __init__(self, attrs=None):
        # Use slightly better defaults than HTML's 20x2 box
        default_attrs = {"style": "width:100%;min-height:400px"}
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

    def render(self, name, value, attrs=None, renderer=None):
        if value is None:
            value = ""
        final_attrs = self.build_attrs(attrs)
        return format_html(
            '<div class="btn-toolbar" data-role="editor-toolbar" data-target=""><div class="btn-group">'
            '<a class="btn btn-default" data-edit="bold" title="Bold (Ctrl/Cmd+B)"><i class="fa-solid fa-bold"></i></a>'
            '<a class="btn btn-default" data-edit="italic" title="Italic (Ctrl/Cmd+I)"><i class="fa-solid fa-italic"></i></a>'
            '<a class="btn btn-default" data-edit="strikethrough" title="Strikethrough">'
            '<i class="fa-solid fa-strikethrough"></i></a>'
            '<a class="btn btn-default" data-edit="underline" title="Underline (Ctrl/Cmd+U)">'
            '<i class="fa-solid fa-underline"></i></a></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="insertunorderedlist" title="Bullet list">'
            '<i class="fa-solid fa-list-ul"></i></a>'
            '<a class="btn btn-default" data-edit="insertorderedlist" title="Number list">'
            '<i class="fa-solid fa-list-ol"></i></a>'
            '<a class="btn btn-default" data-edit="outdent" title="Reduce indent (Shift+Tab)"><i class="fa-solid fa-outdent">'
            '</i></a><a class="btn btn-default" data-edit="indent" title="Indent (Tab)"><i class="fa-solid fa-indent"></i>'
            '</a></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="justifyleft" title="Align Left (Ctrl/Cmd+L)">'
            '<i class="fa-solid fa-align-left"></i></a>'
            '<a class="btn btn-default" data-edit="justifycenter" title="Center (Ctrl/Cmd+E)">'
            '<i class="fa-solid fa-align-center"></i></a>'
            '<a class="btn btn-default" data-edit="justifyright" title="Align Right (Ctrl/Cmd+R)">'
            '<i class="fa-solid fa-align-right"></i></a>'
            '<a class="btn btn-default" data-edit="justifyfull" title="Justify (Ctrl/Cmd+J)">'
            '<i class="fa-solid fa-align-justify"></i></a></div><div class="btn-group">'
            '<a class="btn btn-default dropdown-toggle" data-toggle="dropdown" title="Hyperlink">'
            '<i class="fa-solid fa-link"></i></a><div class="dropdown-menu input-append">'
            '<input placeholder="URL" type="text" data-edit="createLink" />'
            '<button class="btn" type="button">Add</button></div></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="unlink" title="Remove Hyperlink">'
            '<i class="fa-solid fa-link-slash"></i></a></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="undo" title="Undo (Ctrl/Cmd+Z)">'
            '<i class="fa-solid fa-rotate-left"></i></a><a class="btn btn-default" data-edit="redo" title="Redo (Ctrl/Cmd+Y)">'
            '<i class="fa-solid fa-rotate-right"></i></a></div><br/><br/></div><div{}>\r\n{}</div>',
            flatatt(final_attrs),
            force_str(value))


class WYSIWYGContentForm(forms.Form):
    heading = forms.CharField(max_length=200, required=False, initial="Custom Content")
    content = forms.CharField(required=False, widget=Div(attrs={"class": "editor"}))
    hidden_content = forms.CharField(widget=forms.HiddenInput(), required=True)
    page_break_after = forms.BooleanField(required=False, help_text="Include a page break after the custom content.")

    class Meta:
        exclude = []


# base Widget class others will inherit from
class Widget:
    def __init__(self, *args, **kwargs):
        self.title = "Base Widget"
        self.form = None
        self.multiple = "false"
        self.widget_class = "widget"

    @abc.abstractmethod
    def get_html(self, request):
        return

    @abc.abstractmethod
    def get_option_form(self):
        return


class PageBreak(Widget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = "Page Break"
        self.widget_class = "page-break"
        self.form = None
        self.multiple = "true"

    def get_html(self):
        return mark_safe('<div class="report-page-break">Page Break</div>')

    def get_option_form(self):
        return mark_safe(
            "<div data-multiple='true'  class='panel panel-available-widget'><div class='panel-heading' title='Click "
            "and drag to move' data-toggle='tooltip'><div class='clearfix'><h5 style='width: 90%' class='pull-left'>"
            + self.get_html() + "</h5><span class='fa-solid fa-up-down-left-right pull-right icon'></span></div></div>"
            "<form id='page-break'><input type='hidden' name='page-break'/></form></div>")


class ReportOptions(Widget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = "Report Options"
        self.form = CustomReportOptionsForm()
        self.extra_help = "Choose additional report options. These will apply to the overall report."
        self.widget_class = "report-options"

    def get_html(self):
        return mark_safe("")

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)


class CoverPage(Widget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = "Cover Page"
        self.form = CoverPageForm()
        self.help_text = "The cover page includes a page break after its content."
        self.widget_class = "cover-page"

    def get_html(self):
        return render_to_string("dojo/custom_html_report_cover_page.html", {"heading": self.heading,
                                                                            "sub_heading": self.sub_heading,
                                                                            "meta_info": self.meta_info})

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.help_text})
        return mark_safe(html)


class TableOfContents(Widget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = "Table Of Contents"
        self.widget_class = "table-of-contents"
        self.form = TableOfContentsForm()
        self.help_text = "The table of contents includes a page break after its content."

    def get_html(self):
        return render_to_string("dojo/custom_html_toc.html", {"heading": self.heading})

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.help_text})
        return mark_safe(html)


class WYSIWYGContent(Widget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = "Custom Content"
        self.widget_class = "wysiwyg-content"
        self.form = WYSIWYGContentForm()
        self.multiple = "true"

    def get_html(self):
        html = render_to_string(
            "dojo/custom_html_report_wysiwyg_content.html",
            {
                "heading": self.heading,
                "content": self.content,
                "page_break_after": self.page_break_after,
            })
        return mark_safe(html)

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title})
        return mark_safe(html)


class FindingList(Widget):
    def __init__(self, *args, **kwargs):
        if "request" in kwargs:
            self.request = kwargs.get("request")
        if "user_id" in kwargs:
            self.user_id = kwargs.get("user_id")

        if "host" in kwargs:
            self.host = kwargs.get("host")

        if "findings" in kwargs:
            self.findings = kwargs.get("findings")
        else:
            msg = "Need to instantiate with finding queryset."
            raise Exception(msg)

        if "finding_notes" in kwargs:
            self.finding_notes = kwargs.get("finding_notes")
        else:
            self.finding_notes = False

        if "finding_images" in kwargs:
            self.finding_images = kwargs.get("finding_images")
        else:
            self.finding_images = False

        super().__init__(*args, **kwargs)

        self.title = "Finding List"
        if hasattr(self.findings, "form"):
            self.form = self.findings.form
        else:
            self.form = None
        self.multiple = "true"
        self.widget_class = "finding-list"
        self.extra_help = (
            "You can use this form to filter findings and select only the ones to be included in the report."
        )
        self.title_words = get_words_for_field(Finding, "title")
        self.component_words = get_words_for_field(Finding, "component_name")

        if self.request is not None:
            self.paged_findings = get_page_items(self.request, self.findings.qs, 25)
        else:
            self.paged_findings = self.findings

    def get_html(self):
        html = render_to_string("dojo/custom_html_report_finding_list.html",
                                {"title": self.title,
                                 "findings": self.findings.qs,
                                 "include_finding_notes": self.finding_notes,
                                 "include_finding_images": self.finding_images,
                                 "host": self.host,
                                 "user_id": self.user_id})
        return mark_safe(html)

    def get_option_form(self):
        html = render_to_string("dojo/report_findings.html",
                                {"findings": self.paged_findings,
                                 "filtered": self.findings,
                                 "title_words": self.title_words,
                                 "component_words": self.component_words,
                                 "request": self.request,
                                 "title": self.title,
                                 "extra_help": self.extra_help,
                                 })
        return mark_safe(html)


class EndpointList(Widget):
    def __init__(self, *args, **kwargs):
        if "request" in kwargs:
            self.request = kwargs.get("request")
        if "user_id" in kwargs:
            self.user_id = kwargs.get("user_id")

        if "host" in kwargs:
            self.host = kwargs.get("host")

        if "endpoints" in kwargs:
            self.endpoints = kwargs.get("endpoints")
        else:
            msg = "Need to instantiate with endpoint queryset."
            raise Exception(msg)

        if "finding_notes" in kwargs:
            self.finding_notes = kwargs.get("finding_notes")
        else:
            self.finding_notes = False

        if "finding_images" in kwargs:
            self.finding_images = kwargs.get("finding_images")
        else:
            self.finding_images = False

        super().__init__(*args, **kwargs)

        self.title = "Endpoint List"
        self.form = self.endpoints.form
        self.multiple = "false"
        self.widget_class = "endpoint-list"
        if self.request is not None:
            self.paged_endpoints = get_page_items(self.request, self.endpoints.qs, 25)
        else:
            self.paged_endpoints = self.endpoints
        self.multiple = "true"
        self.extra_help = (
            "You can use this form to filter endpoints and select only the ones to be included in the report."
        )

    def get_html(self):
        html = render_to_string("dojo/custom_html_report_endpoint_list.html",
                                {"title": self.title,
                                 "endpoints": self.endpoints.qs,
                                 "include_finding_notes": self.finding_notes,
                                 "include_finding_images": self.finding_images,
                                 "host": self.host,
                                 "user_id": self.user_id})
        return mark_safe(html)

    def get_option_form(self):
        html = render_to_string("dojo/report_endpoints.html",
                                {"endpoints": self.paged_endpoints,
                                 "filtered": self.endpoints,
                                 "request": self.request,
                                 "title": self.title,
                                 "extra_help": self.extra_help,
                                 })
        return mark_safe(html)


def report_widget_factory(json_data=None, request=None, user=None, *, finding_notes=False, finding_images=False,
                          host=None):
    selected_widgets = OrderedDict()
    widgets = json.loads(json_data)

    for idx, widget in enumerate(widgets):
        if list(widget.keys())[0] == "page-break":
            selected_widgets[list(widget.keys())[0] + "-" + str(idx)] = PageBreak()

        if list(widget.keys())[0] == "endpoint-list":
            endpoints = Endpoint.objects.filter(finding__active=True,
                                                finding__false_p=False,
                                                finding__duplicate=False,
                                                finding__out_of_scope=False,
                                                )
            if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
                endpoints = endpoints.filter(finding__verified=True)

            endpoints = endpoints.distinct()

            d = QueryDict(mutable=True)
            for item in widget.get(list(widget.keys())[0]):
                if item["name"] in d:
                    d.appendlist(item["name"], item["value"])
                else:
                    d[item["name"]] = item["value"]

            endpoints = Endpoint.objects.filter(id__in=endpoints)
            filter_string_matching = get_system_setting("filter_string_matching", False)
            filter_class = EndpointFilterWithoutObjectLookups if filter_string_matching else EndpointFilter
            endpoints = filter_class(d, queryset=endpoints, user=request.user)
            user_id = user.id if user is not None else None
            endpoints = EndpointList(request=request, endpoints=endpoints, finding_notes=finding_notes,
                                     finding_images=finding_images, host=host, user_id=user_id)

            selected_widgets[list(widget.keys())[0] + "-" + str(idx)] = endpoints

        if list(widget.keys())[0] == "finding-list":
            findings = Finding.objects.all()
            d = QueryDict(mutable=True)
            for item in widget.get(list(widget.keys())[0]):
                if item["name"] in d:
                    d.appendlist(item["name"], item["value"])
                else:
                    d[item["name"]] = item["value"]
            filter_string_matching = get_system_setting("filter_string_matching", False)
            filter_class = ReportFindingFilterWithoutObjectLookups if filter_string_matching else ReportFindingFilter
            findings = filter_class(d, queryset=findings)
            user_id = user.id if user is not None else None
            selected_widgets[list(widget.keys())[0] + "-" + str(idx)] = FindingList(request=request, findings=findings,
                                                                              finding_notes=finding_notes,
                                                                              finding_images=finding_images,
                                                                              host=host, user_id=user_id)

        if list(widget.keys())[0] == "custom-content":
            wysiwyg_content = WYSIWYGContent(request=request)
            wysiwyg_content.heading = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "heading"), None)["value"]
            wysiwyg_content.content = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "hidden_content"), None)["value"]
            wysiwyg_content.page_break_after = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "page_break_after"),
                     {"value": False})["value"]
            selected_widgets[list(widget.keys())[0] + "-" + str(idx)] = wysiwyg_content
        if list(widget.keys())[0] == "report-options":
            options = ReportOptions(request=request)
            options.include_finding_notes = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "include_finding_notes"), None)[
                    "value"]
            options.include_finding_images = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "include_finding_images"), None)[
                    "value"]
            options.report_type = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "report_type"), None)["value"]
            options.report_name = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "report_name"), None)["value"]
            selected_widgets[list(widget.keys())[0]] = options
        if list(widget.keys())[0] == "table-of-contents":
            toc = TableOfContents(request=request)
            toc.heading = next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "heading"), None)[
                "value"]
            selected_widgets[list(widget.keys())[0]] = toc
        if list(widget.keys())[0] == "cover-page":
            cover_page = CoverPage(request=request)
            cover_page.heading = next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "heading"), None)[
                "value"]
            cover_page.sub_heading = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "sub_heading"), None)["value"]
            cover_page.meta_info = \
                next((item for item in widget.get(list(widget.keys())[0]) if item["name"] == "meta_info"), None)["value"]
            selected_widgets[list(widget.keys())[0]] = cover_page

    return selected_widgets
