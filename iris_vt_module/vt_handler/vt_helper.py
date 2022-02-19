import traceback

from jinja2 import Template
import logging
from iris_interface import IrisInterfaceStatus

log = logging.getLogger('iris_vt_module.vt_helper')


def gen_domain_report_from_template(html_template, vt_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for domains, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param vt_report: The JSON report fetched with VT API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = vt_report

    if "detected_urls" in context:
        context["nb_detected_urls"] = len(context["detected_urls"])
        count_total = 0
        count_positives = 0

        for detected_url in context["detected_urls"]:
            count_total += detected_url.get('total')
            count_positives += detected_url.get('positives')

        if context['nb_detected_urls'] > 0:
            context["avg_urls_detect_ratio"] = f"{round(count_positives/context['nb_detected_urls'], 2)} / " \
                                              f"{count_total/context['nb_detected_urls']}"
        else:
            context["avg_urls_detect_ratio"] = "No information"

    if "detected_downloaded_samples" in context:
        context["nb_detected_samples"] = len(context["detected_downloaded_samples"])
        count_total = 0
        count_positives = 0

        for samples in context["detected_downloaded_samples"]:
            count_total += samples.get('total')
            count_positives += samples.get('positives')

        if context['nb_detected_samples'] > 0:
            context["avg_samples_detect_ratio"] = f"{round(count_positives/context['nb_detected_samples'], 2)} / " \
                                                  f"{count_total/context['nb_detected_samples']}"
        else:
            context["avg_samples_detect_ratio"] = "No information"

    try:

        rendered = template.render(context)

    except Exception:
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)


def gen_ip_report_from_template(html_template, vt_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for IP, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param vt_report: The JSON report fetched with VT API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = vt_report

    if "detected_urls" in context:
        context["nb_detected_urls"] = len(context["detected_urls"])
        count_total = 0
        count_positives = 0

        for detected_url in context["detected_urls"]:
            count_total += detected_url.get('total')
            count_positives += detected_url.get('positives')

        if context['nb_detected_urls'] > 0:
            context["avg_urls_detect_ratio"] = f"{round(count_positives/context['nb_detected_urls'], 2)} / " \
                                              f"{count_total/context['nb_detected_urls']}"
        else:
            context["avg_urls_detect_ratio"] = "No information"

    if "detected_communicating_samples" in context:
        context["nb_detected_samples"] = len(context["detected_communicating_samples"])
        count_total = 0
        count_positives = 0

        for samples in context["detected_communicating_samples"]:
            count_total += samples.get('total')
            count_positives += samples.get('positives')

        if context['nb_detected_samples'] > 0:
            context["avg_samples_detect_ratio"] = f"{round(count_positives/context['nb_detected_samples'], 2)} / " \
                                                  f"{count_total/context['nb_detected_samples']}"
        else:
            context["avg_samples_detect_ratio"] = "No information"

    try:

        rendered = template.render(context)

    except Exception:
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)